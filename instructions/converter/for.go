package converter

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dexnore/dexfile/instructions/parser"
)

type forAction string

const (
	ActionForIn forAction = "in"
)

type CommandFor struct {
	withNameAndCode
	Commands []Command
	Delim    string
	Action   forAction
	EXEC     Command
	TimeOut  *time.Duration
	As       string
}

type CommandEndFor struct {
	withNameAndCode
}

func (c *CommandFor) AddCommand(cmd Command) {
	c.Commands = append(c.Commands, cmd)
}

func parseFor(req parseRequest) (forcmd *CommandFor, err error) {
	forcmd = &CommandFor{withNameAndCode: newWithNameAndCode(req)}
	if len(req.args) <= 3 {
		return nil, fmt.Errorf("FOR requires three arguments")
	}

	forcmd.As = req.args[0]
	action := strings.ToUpper(strings.TrimSpace(req.args[1]))
	switch action {
	case "IN":
		forcmd.Action = ActionForIn
	default:
		return nil, fmt.Errorf("%s not supported by FOR instruction", action)
	}

	flDelim := req.flags.AddString("delim", "")
	flTimeout := req.flags.AddString("timeout", "")
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}
	forcmd.Delim = flDelim.Value

	original := strings.TrimSpace(strings.Join(req.args[2:], " "))
	res, err := parser.Parse(strings.NewReader(original))
	if err != nil || res == nil {
		return nil, errors.Join(
			fmt.Errorf(
				"failed to parse [FOR] condition. Please check your syntax and ensure all required fields are present. Input was:\n%s",
				original,
			),
			err,
		)
	}

	cmd, err := ParseCommand(res.AST.Children[0])
	if err != nil {
		return nil, err
	}

	switch cmd.(type) {
	case *RunCommand, *CommandExec, *CommandProcess:
		forcmd.EXEC = cmd
		if err := req.flags.Parse(); err != nil {
			return nil, err
		}

		timeout, err := parseOptInterval(flTimeout)
		if err != nil {
			return nil, err
		}
		if _, ok := req.flags.used["timeout"]; ok {
			forcmd.TimeOut = &timeout
		} else {
			dur := 10 * time.Minute
			forcmd.TimeOut = &dur
		}
	default:
		return nil, parser.WithLocation(fmt.Errorf("unsupported For command: %s", cmd.Name()), cmd.Location())
	}

	return forcmd, nil
}

func parseEndFor(req parseRequest) (*CommandEndFor, error) {
	endFor := &CommandEndFor{
		withNameAndCode: newWithNameAndCode(req),
	}
	if len(req.args) > 0 {
		if s := strings.TrimSpace(strings.Join(req.args, " ")); s != "" {
			return nil, &UnknownInstructionError{Instruction: s, Line: req.location[0].Start.Line}
		}
	}

	return endFor, nil
}
