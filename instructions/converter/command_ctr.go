package converter

import (
	"fmt"
	"regexp"
	"time"

	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
)

type CommandConatainer struct {
	withNameAndCode
	From     string
	Commands []Command
	Parent   *CommandConatainer
}

type EndContainer struct {
	withNameAndCode
}

type CommandProcess struct {
	withNameAndCode
	TimeOut     *time.Duration
	RUN         RunCommand
	Result      *client.Result
	FROM        llb.State
	BaseImage   string
	InContainer *CommandConatainer
}

func (c *CommandConatainer) AddCommand(cmd Command) {
	c.Commands = append(c.Commands, cmd)
}

func (c *CommandConatainer) ParentCtr(ctr *CommandConatainer) {
	c.Parent = ctr
}

func parseCtr(req parseRequest) (ctr *CommandConatainer, err error) {
	ctr = &CommandConatainer{withNameAndCode: newWithNameAndCode(req)}

	flFrom := req.flags.AddString("from", "")
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	ctr.From = flFrom.Value
	return ctr, nil
}

func parseEndCtr(req parseRequest) (endCtr *EndContainer, err error) {
	endCtr = &EndContainer{withNameAndCode: newWithNameAndCode(req)}
	if len(req.args) > 0 {
		original := regexp.MustCompile(`(?i)^\s*ENDCTR\s*`).ReplaceAllString(req.original, "")
		for _, heredoc := range req.heredocs {
			original += "\n" + heredoc.Content + heredoc.Name
		}
		if len(original) > 0 {
			return nil, parser.WithLocation(&UnknownInstructionError{Instruction: original, Line: req.location[0].Start.Line}, endCtr.Location())
		}
	}

	return endCtr, nil
}

func parseProc(req parseRequest) (proc *CommandProcess, err error) {
	proc = &CommandProcess{withNameAndCode: newWithNameAndCode(req)}
	run, err := parseRun(req)
	if err != nil {
		return nil, err
	}

	if run == nil {
		return nil, fmt.Errorf("unable to to parse [PROC] command")
	}

	proc.RUN = *run
	flTimeout := req.flags.AddString("timeout", "")
	flFrom := req.flags.AddString("from", "")
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}
	proc.BaseImage = flFrom.Value

	timeout, err := parseOptInterval(flTimeout)
	if err != nil {
		return nil, err
	}
	if _, ok := req.flags.used["timeout"]; ok {
		proc.TimeOut = &timeout
	} else {
		dur := 10 * time.Minute
		proc.TimeOut = &dur
	}
	return proc, nil
}
