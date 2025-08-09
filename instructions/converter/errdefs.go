package converter

import (
	"fmt"

	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/pkg/errors"
)

// UnknownInstructionError represents an error occurring when a command is unresolvable
type UnknownInstructionError struct {
	Line        int
	Instruction string
}

func (e *UnknownInstructionError) Error() string {
	return fmt.Sprintf("unknown instruction: %q", e.Instruction)
}

type parseError struct {
	inner error
	node  *parser.Node
}

func (e *parseError) Error() string {
	return fmt.Sprintf("dexfile parse error on line %d: %v", e.node.StartLine, e.inner.Error())
}

func (e *parseError) Unwrap() error {
	return e.inner
}

func errAtLeastOneArgument(command string) error {
	return errors.Errorf("%s requires at least one argument", command)
}

func errExactlyOneArgument(command string) error {
	return errors.Errorf("%s requires exactly one argument", command)
}

func errNoDestinationArgument(command string) error {
	return errors.Errorf("%s requires at least two arguments, but only one was provided. Destination could not be determined", command)
}

func errBadHeredoc(command string, option string) error {
	return errors.Errorf("%s cannot accept a heredoc as %s", command, option)
}

func errBlankCommandNames(command string) error {
	return errors.Errorf("%s names can not be blank", command)
}

func errTooManyArguments(command string) error {
	return errors.Errorf("Bad input to %s, too many arguments", command)
}
