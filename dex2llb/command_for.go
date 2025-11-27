package dex2llb

import (
	"context"
	"fmt"
	"slices"

	"github.com/dexnore/dexfile/dex2llb/internal"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/identity"
)

var supportedForActions = []converter.ForAction{
	converter.ActionForIn,
}

func handleForLoop(ctx context.Context, d *dispatchState, cmd converter.CommandFor, exec func(*dispatchState, []converter.Command, ...llb.ConstraintsOpt) (bool, error), opt dispatchOpt, copts ...llb.ConstraintsOpt) (breakCmd bool, err error) {
	if !slices.Contains(supportedForActions, cmd.Action) {
		return false, fmt.Errorf("unsupported 'for' action: %s", cmd.Action)
	}

	ds := d.Clone()
	dOpt, err := opt.Clone()
	if err != nil {
		return false, err
	}

	switch exec := cmd.EXEC.(type) {
	case *converter.CommandProcess:
		c, err := toCommand(exec, dOpt.allDispatchStates)
		if err != nil {
			return false, err
		}
		if _, err := dispatch(ctx, ds, c, dOpt); err != nil {
			return false, err
		}
	case *converter.RunCommand:
		c, err := toCommand(exec, dOpt.allDispatchStates)
		if err != nil {
			return false, err
		}
		if err := dispatchProc(ctx, ds, &converter.CommandProcess{
			TimeOut:    cmd.TimeOut,
			RunCommand: *exec,
		}, dOpt.proxyEnv, c.sources, dOpt); err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("unsupported [FOR] command exec: %s", exec.Name())
	}
	var regexOutput []string
	switch stdout := internal.Stdout(ds.state); cmd.Regex.Action {
	case converter.ActionRegexSplit:
		regexOutput = cmd.Regex.Regex.Split(stdout, -1)
	case converter.ActionRegexMatch:
		regexOutput = cmd.Regex.Regex.FindAllString(stdout, -1)
	default:
		return breakCmd, fmt.Errorf("unsupported regex action: %s", cmd.Regex.Action)
	}

	forID := identity.NewID()
	localCopts := []llb.ConstraintsOpt{
		llb.WithCaps(*opt.llbCaps),
		llb.ProgressGroup(forID, fmt.Sprintf("FOR %+v", cmd.EXEC), false),
	}
	LocalCopts := append(copts, localCopts...)

	d.state = d.state.AddEnv("LENGTH", fmt.Sprintf("%d", len(regexOutput)))
	for i, dv := range regexOutput {
		d.state = d.state.
			AddEnv(cmd.As, dv).
			AddEnv("INDEX", fmt.Sprintf("%d", i))
		if breakCmd, err = exec(d, cmd.Commands, append(LocalCopts, llb.WithCustomNamef("FOR [%s=%s]", cmd.As, dv))...); err != nil {
			return breakCmd, err
		}
		if breakCmd {
			return true, nil
		}
	}

	return false, err
}
