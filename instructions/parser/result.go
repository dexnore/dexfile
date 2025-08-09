package parser

import (
	"fmt"
	"io"
)

// Result contains the bundled outputs from parsing a Dexfile.
type Result struct {
	AST         *Node
	EscapeToken rune
	Warnings    []Warning
}

// Warning contains information to identify and locate a warning generated
// during parsing.
type Warning struct {
	Short    string
	Detail   [][]byte
	URL      string
	Location *Range
}

// PrintWarnings to the writer
func (r *Result) PrintWarnings(out io.Writer) {
	if len(r.Warnings) == 0 {
		return
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(out, "[WARNING]: %s\n", w.Short)
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintf(out, "[WARNING]: Empty continuation lines will become errors in a future release.\n")
	}
}
