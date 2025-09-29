package converter

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
)

type CommandContainer struct {
	withNameAndCode
	From      string
	as        string
	Container client.Container
	Result    *client.Result
	State     llb.State
	Commands  []Command
	parent    *CommandContainer
	withExternalData
}

type EndContainer struct {
	withNameAndCode
}

type CommandProcess struct {
	withNameAndCode
	TimeOut     *time.Duration
	RUN         RunCommand
	From        string
	InContainer CommandContainer
}

func (c *CommandContainer) Clone() *CommandContainer {
	var parent *CommandContainer
	if c.parent != nil {
		parent = c.parent.Clone()
	}

	var result *client.Result
	if c.Result != nil {
		result = c.Result.Clone()
	}

	return &CommandContainer{
		withNameAndCode: c.withNameAndCode,
		as:              c.as,
		parent:          parent,
		From:            c.From,
		Container:       c.Container,
		Result:          result,
		State:           c.State,
		Commands:        slices.Clone(c.Commands),
	}
}

func (c *CommandContainer) Expand(expander SingleWordExpander) error {
	if err := setMountState(&c.withExternalData, expander); err != nil {
		return err
	}
	return nil
}

func (c *CommandContainer) AddCommand(cmd Command) {
	c.Commands = append(c.Commands, cmd)
}

func (c *CommandContainer) ParentCtr(ctr *CommandContainer) {
	c.parent = ctr.Clone()
}

func (c *CommandContainer) FindContainer(from string) (ctr *CommandContainer, ok bool) {
	if c.as == from {
		return c, true
	}

	if c.parent == nil {
		return nil, false
	}

	return c.parent.FindContainer(from)
}

func (c *CommandProcess) FindContainer(from string) (ctr *CommandContainer, ok bool) {
	return c.InContainer.FindContainer(from)
}

func parseCtr(req parseRequest) (ctr *CommandContainer, err error) {
	ctr = &CommandContainer{withNameAndCode: newWithNameAndCode(req)}
	ctr.as, ctr.From, err = parseCtrName(req.args)
	if err != nil {
		return nil, err
	}
	for _, fn := range parseRunPreHooks {
		if err := fn(ctr, req); err != nil {
			return nil, err
		}
	}

	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	for _, fn := range parseRunPostHooks {
		if err := fn(ctr, req); err != nil {
			return nil, err
		}
	}

	return ctr, err
}

func parseCtrName(args []string) (as, from string, err error) {
	switch {
	case len(args) == 3 && strings.EqualFold(args[1], "from"):
		from = strings.ToLower(args[2])
		if _, err := reference.Parse(from); err != nil {
			return "", "", fmt.Errorf("invalid 'from' for container: %q, name can't start with a number or contain symbols\n%w", args[2], err)
		}
	case len(args) != 1:
		return "", "", fmt.Errorf("FROM requires either one or three arguments")
	}

	return as, from, nil
}

func parseEndCtr(req parseRequest) (endCtr *EndContainer, err error) {
	endCtr = &EndContainer{withNameAndCode: newWithNameAndCode(req)}
	if len(req.args) > 0 {
		if s := strings.TrimSpace(strings.Join(req.args, " ")); s != "" {
			return nil, &UnknownInstructionError{Instruction: s, Line: req.location[0].Start.Line}
		}
	}

	return endCtr, nil
}

func parseProc(req parseRequest) (proc *CommandProcess, err error) {
	proc = &CommandProcess{withNameAndCode: newWithNameAndCode(req)}
	flTimeout := req.flags.AddString("timeout", "")
	flFrom := req.flags.AddString("from", "")
	run, err := parseRun(req)
	if err != nil {
		return nil, err
	}

	if run == nil {
		return nil, fmt.Errorf("unable to to parse [PROC] command")
	}

	proc.RUN = *run
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}
	proc.From = flFrom.Value
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
