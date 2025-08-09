package parser

import (
	"regexp"

	"github.com/pkg/errors"
)

// directives is the structure used during a build run to hold the state of
// parsing directives.
type directives struct {
	parser                DirectiveParser
	escapeToken           rune           // Current escape token
	lineContinuationRegex *regexp.Regexp // Current line continuation regex
}

// setEscapeToken sets the default token for escaping characters and as line-
// continuation token in a Dexfile. Only ` (backtick) and \ (backslash) are
// allowed as token.
func (d *directives) setEscapeToken(s string) error {
	if s != "`" && s != `\` {
		return errors.Errorf("invalid escape token '%s' does not match ` or \\", s)
	}
	d.escapeToken = rune(s[0])
	// The escape token is used both to escape characters in a line and as line
	// continuation token. If it's the last non-whitespace token, it is used as
	// line-continuation token, *unless* preceded by an escape-token.
	//
	// The second branch in the regular expression handles line-continuation
	// tokens on their own line, which don't have any character preceding them.
	//
	// Due to Go lacking negative look-ahead matching, this regular expression
	// does not currently handle a line-continuation token preceded by an *escaped*
	// escape-token ("foo \\\").
	d.lineContinuationRegex = regexp.MustCompile(`([^\` + s + `])\` + s + `[ \t]*$|^\` + s + `[ \t]*$`)
	return nil
}

// possibleParserDirective looks for parser directives, eg '# escapeToken=<char>'.
// Parser directives must precede any builder instruction or other comments,
// and cannot be repeated. Returns true if a parser directive was found.
func (d *directives) possibleParserDirective(line []byte) (bool, error) {
	directive, err := d.parser.ParseLine(line)
	if err != nil {
		return false, err
	}
	if directive != nil && directive.Name == keyEscape {
		err := d.setEscapeToken(directive.Value)
		return err == nil, err
	}
	return directive != nil, nil
}

// newDefaultDirectives returns a new directives structure with the default escapeToken token
func newDefaultDirectives() *directives {
	d := &directives{}
	d.setEscapeToken(string(DefaultEscapeToken))
	return d
}
