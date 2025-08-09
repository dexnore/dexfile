package parser

import (
	"fmt"
	"strconv"
	"strings"
)

// Node is a structure used to represent a parse tree.
//
// In the node there are three fields, Value, Next, and Children. Value is the
// current token's string value. Next is always the next non-child token, and
// children contains all the children. Here's an example:
//
// (value next (child child-next child-next-next) next-next)
//
// This data structure is frankly pretty lousy for handling complex languages,
// but lucky for us the Dexfile isn't very complicated. This structure
// works a little more effectively than a "proper" parse tree for our needs.
type Node struct {
	Value       string          // actual content
	Next        *Node           // the next item in the current sexp
	Children    []*Node         // the children of this sexp
	Heredocs    []Heredoc       // extra heredoc content attachments
	Attributes  map[string]bool // special attributes for this node
	Original    string          // original line used before parsing
	Flags       []string        // only top Node should have this set
	StartLine   int             // the line in the original dexfile where the node begins
	EndLine     int             // the line in the original dexfile where the node ends
	PrevComment []string
}

// newNodeFromLine splits the line into parts, and dispatches to a function
// based on the command and command arguments. A Node is created from the
// result of the dispatch.
func newNodeFromLine(line string, d *directives, comments []string) (*Node, error) {
	cmd, flags, args, err := splitCommand(line, d)
	if err != nil {
		return nil, err
	}

	fn := dispatch[strings.ToLower(cmd)]
	// Ignore invalid Dexfile instructions
	if fn == nil {
		fn = parseIgnore
	}
	next, attrs, err := fn(args, d)
	if err != nil {
		return nil, err
	}

	return &Node{
		Value:       cmd,
		Original:    line,
		Flags:       flags,
		Next:        next,
		Attributes:  attrs,
		PrevComment: comments,
	}, nil
}

// Location return the location of node in source code
func (node *Node) Location() []Range {
	return toRanges(node.StartLine, node.EndLine)
}

// Dump dumps the AST defined by `node` as a list of sexps.
// Returns a string suitable for printing.
func (node *Node) Dump() string {
	str := strings.ToLower(node.Value)

	if len(node.Flags) > 0 {
		str += fmt.Sprintf(" %q", node.Flags)
	}

	for _, n := range node.Children {
		str += "(" + n.Dump() + ")\n"
	}

	for n := node.Next; n != nil; n = n.Next {
		if len(n.Children) > 0 {
			str += " " + n.Dump()
		} else {
			str += " " + strconv.Quote(n.Value)
		}
	}

	return strings.TrimSpace(str)
}

func (node *Node) lines(start, end int) {
	node.StartLine = start
	node.EndLine = end
}

func (node *Node) canContainHeredoc() bool {
	// check for compound commands, like ONBUILD
	if ok := heredocCompoundDirectives[strings.ToLower(node.Value)]; ok {
		if node.Next != nil && len(node.Next.Children) > 0 {
			node = node.Next.Children[0]
		}
	}

	if ok := heredocDirectives[strings.ToLower(node.Value)]; !ok {
		return false
	}
	if isJSON := node.Attributes["json"]; isJSON {
		return false
	}

	return true
}

// AddChild adds a new child node, and updates line information
func (node *Node) AddChild(child *Node, startLine, endLine int) {
	child.lines(startLine, endLine)
	if node.StartLine < 0 {
		node.StartLine = startLine
	}
	node.EndLine = endLine
	node.Children = append(node.Children, child)
}
