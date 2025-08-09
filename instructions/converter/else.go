package converter

import (
	"regexp"
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
type ConditionElse struct {
	withNameAndCode
	// just ConditionIF fields
	Condition Command
	TimeOut   *time.Duration
	Commands  []Command
	End       bool
}

// AddCommand appends a command to the IF block.
func (c *ConditionElse) AddElse(cmd Command) error {
	if c.End {
		return errors.New("cannot add commands to Conditional Else block: the block has already been closed")
	}

	c.Commands = append(c.Commands, cmd)
	return nil
}

func (c *ConditionElse) EndElse() {
	c.End = true
}

func (c *ConditionElse) ElseIf() bool {
	return c.Condition != nil
}

func parseElse(req parseRequest) (elsecmd *ConditionElse, err error) {
	elsecmd = &ConditionElse{}
	elsecmd.withNameAndCode = newWithNameAndCode(req)
	if len(req.args) > 0 {
		// else sub-command
		original := regexp.MustCompile(`(?i)^\s*ELSE\s*`).ReplaceAllString(req.original, "")
		for _, heredoc := range req.heredocs {
			original += "\n" + heredoc.Content + heredoc.Name
		}

		res, _ := parser.Parse(strings.NewReader(original))
		// if err == nil {
		// 	return elsecmd, nil
		// 	// errors.Wrapf(err, "failed to parse [ELSE] block. Please check your syntax and ensure all required fields are present. Input was:\n%s", original)
		// }

		if res != nil {
			if len(res.AST.Children) != 1 {
				return nil, errors.New("else command should have single IF condition")
			}
			cmd, err := parseIf(newParseRequestFromNode(res.AST.Children[0]))
			if err != nil {
				return nil, err
			}
			elsecmd.Commands = cmd.Commands
			elsecmd.Condition = cmd.Condition
			elsecmd.TimeOut = cmd.TimeOut
			elsecmd.End = cmd.End
		}
	}
	// else
	// 		some-instruction
	// endif
	return elsecmd, nil
}
