package converter

import (
	"slices"
	"strings"
	"time"

	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/pkg/errors"
)

// IfCommand allows conditional execution of commands based on the result of a
// previous command. It can run a command if the previous command succeeded,
// or run an alternative command if the previous command failed.
//
//	IF <previous command>
//		<command to run if previous succeeded>
//	ELSE
//		<command to run if previous failed>
//	ENDIF
//
// The `IF` command checks the exit status of the previous command. If it was
// successful (exit status 0), it runs the command specified with in if-else block. If
// the previous command failed (non-zero exit status), it runs the command
// specified after `ELSE`. The `ENDIF` command marks the end of the conditional
// block.
type ConditionIF struct {
	withNameAndCode
	Condition Command
	TimeOut   *time.Duration
	Commands  []Command
	End       bool
}

func (c *ConditionIF) AddCommand(cmd Command) error {
	if c.End {
		return errors.New("cannot add commands to Conditional IF block: the block has already been closed")
	}
	c.Commands = append(c.Commands, cmd)
	return nil
}

func (c *ConditionIF) EndBlock() {
	c.End = true
}

type ConditionIfElse struct {
	*ConditionIF
	ConditionElse []*ConditionElse
	withNameAndCode
}

func (c *ConditionIfElse) Name() string {
	return "IF/ELSE"
}

func (c *ConditionIfElse) Location() (loc []parser.Range) {
	loc = c.ConditionIF.Location()
	for _, l := range c.ConditionElse {
		loc = append(loc, l.Location()...)
	}

	return loc
}

func parseIf(req parseRequest) (ifcmd *ConditionIF, err error) {
	ifcmd = &ConditionIF{}
	ifcmd.withNameAndCode = newWithNameAndCode(req)
	if len(req.args) == 0 {
		return nil, errors.Errorf("invalid [IF] statement: missing condition. Please specify a subcommand, e.g., 'IF RUN ...'")
	}

	original := strings.TrimSpace(strings.Join(req.args[0:], " "))

	res, err := parser.Parse(strings.NewReader(original))
	if err != nil || res == nil {
		return nil, errors.Wrapf(
			err,
			"failed to parse [IF] condition. Please check your syntax and ensure all required fields are present. Input was:\n%s",
			original,
		)
	}

	if len(res.AST.Children) != 1 {
		return nil, errors.New("'if' command should have single condition")
	}

	cond, err := ParseCommand(res.AST.Children[0])
	if err != nil {
		return nil, err
	}

	switch cond.(type) {
	case *RunCommand, *CommandExec, *CommandProcess, *CommandBuild:
		flTimeout := req.flags.AddString("timeout", "")
		if err := req.flags.Parse(); err != nil {
			return nil, err
		}

		timeout, err := parseOptInterval(flTimeout)
		if err != nil {
			return nil, err
		}
		if used := req.flags.Used(); slices.Contains(used, "timeout") {
			ifcmd.TimeOut = &timeout
		} else {
			dur := 10 * time.Minute
			ifcmd.TimeOut = &dur
		}

		ifcmd.Condition = cond
	default:
		return nil, errors.Errorf("unknown subcommand [%s] in [IF] statement", cond.Name())
	}

	return ifcmd, nil
}
