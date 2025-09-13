package dex2llb

import (
	"context"
	"fmt"
	"strings"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
)

func dispatchFunction(ctx context.Context, d *dispatchState, cmd converter.Function, opt dispatchOpt, copts ...llb.ConstraintsOpt) (breakCmd bool, err error) {
	defer func() {
		if err != nil {
			err = parser.WithLocation(err, cmd.Location())
		}
	}()
	if cmd.Action != nil {
		if strings.EqualFold(*cmd.Action, "call") {
			return handleFunctionCall(ctx, cmd, d, opt, copts...)
		}

		return false, fmt.Errorf("unsupported function action: %q", *cmd.Action)
	}
	return false, handleFunctionDefination(cmd, opt)
}

func handleFunctionCall(ctx context.Context, cmd converter.Function, d *dispatchState, opt dispatchOpt, copts ...llb.ConstraintsOpt) (breakCmd bool, err error) {
	var (
		function *converter.Function
		ok       bool
	)
	if function, ok = opt.functions[cmd.FuncName]; !ok {
		return false, fmt.Errorf("unknown function: %q", cmd.FuncName)
	}

	var funcArgs = append(function.Args, cmd.Args...)
	ds := d.Clone()
	dOpt, err := opt.Clone()
	if err != nil {
		return false, err
	}
	for _, kvp := range funcArgs {
		ds.opt.buildArgValues[kvp.Key] = kvp.ValueString()
		ds.state = ds.state.AddEnv(kvp.Key, kvp.ValueString())
	}
	for _, cmd := range function.Commands {
		ic, err := toCommand(cmd, dOpt.allDispatchStates)
		if err != nil {
			return false, err
		}
		if breakCmd, err = dispatch(ctx, ds, ic, dOpt, copts...); err != nil {
			return breakCmd, err
		}
		if breakCmd {
			return true, nil
		}
	}

	localCopt := []llb.ConstraintsOpt{
		llb.WithCaps(*dOpt.llbCaps),
		llb.WithCustomNamef("FUNC CALL %s", cmd.FuncName),
	}

	LocalCopts := append(copts, localCopt...)

	if opt.llbCaps.Supports(pb.CapMergeOp) == nil {
		d.state = llb.Merge([]llb.State{d.state, llb.Diff(d.state, ds.state, LocalCopts...)})
	} else {
		d.state = d.state.File(llb.Copy(ds.state, "/", "/"), LocalCopts...)
	}
	return false, nil
}

func handleFunctionDefination(cmd converter.Function, opt dispatchOpt) error {
	opt.functions[cmd.FuncName] = &cmd
	return nil
}
