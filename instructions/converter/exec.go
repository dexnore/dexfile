package converter

import "time"

type CommandExec struct {
	withNameAndCode
	TimeOut *time.Duration
	RUN     *RunCommand
}

func parseExec(req parseRequest) (exec *CommandExec, err error) {
	exec = &CommandExec{withNameAndCode: newWithNameAndCode(req)}
	
	flTimeout := req.flags.AddString("timeout", "")
	exec.RUN, err = parseRun(req)
	if err != nil {
		return nil, err
	}

	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	timeout, err := parseOptInterval(flTimeout)
	if err != nil {
		return nil, err
	}
	if _, ok := req.flags.used["timeout"]; ok {
		exec.TimeOut = &timeout
	} else {
		dur := 10 * time.Minute
		exec.TimeOut = &dur
	}

	return exec, err
}
