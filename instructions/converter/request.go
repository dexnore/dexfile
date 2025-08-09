package converter

import "github.com/dexnore/dexfile/instructions/parser"

type parseRequest struct {
	command    string
	args       []string
	heredocs   []parser.Heredoc
	attributes map[string]bool
	flags      *BFlags
	original   string
	location   []parser.Range
	comments   []string
}

func nodeArgs(node *parser.Node) []string {
	result := []string{}
	for ; node.Next != nil; node = node.Next {
		arg := node.Next
		if len(arg.Children) == 0 {
			result = append(result, arg.Value)
		} else if len(arg.Children) == 1 {
			// sub command
			result = append(result, arg.Children[0].Value)
			result = append(result, nodeArgs(arg.Children[0])...)
		}
	}
	return result
}

func newParseRequestFromNode(node *parser.Node) parseRequest {
	return parseRequest{
		command:    node.Value,
		args:       nodeArgs(node),
		heredocs:   node.Heredocs,
		attributes: node.Attributes,
		original:   node.Original,
		flags:      NewBFlagsWithArgs(node.Flags),
		location:   node.Location(),
		comments:   node.PrevComment,
	}
}
