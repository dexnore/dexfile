package converter

import (
	"time"
)

type CommandProcess struct {
	TimeOut *time.Duration
	RunCommand
	From string
}

func (c *CommandProcess) Expand(expander SingleWordExpander) error {
	if err := setMountState(c, expander); err != nil {
		return err
	}
	return nil
}

func parseProc(req parseRequest) (proc *CommandProcess, err error) {
	proc = &CommandProcess{}
	flTimeout := req.flags.AddString("timeout", "")
	flFrom := req.flags.AddString("from", "")
	run, err := parseRun(req)
	if err != nil {
		return nil, err
	}

	proc.RunCommand = *run
	proc.From = flFrom.Value
	timeout, err := parseOptInterval(flTimeout)
	if err != nil {
		return nil, err
	}
	if _, ok := req.flags.used["timeout"]; ok {
		proc.TimeOut = &timeout
	} else {
		dur := 10 * time.Second
		proc.TimeOut = &dur
	}

	return proc, nil
}
