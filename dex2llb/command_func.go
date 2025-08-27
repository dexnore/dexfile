package dex2llb

import (
	// "bytes"
	"context"
	"fmt"
	"strings"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
)

func dispatchFunction(ctx context.Context, d *dispatchState, cmd converter.Function, opt dispatchOpt) (err error) {
	defer func() {
		if err != nil {
			err = parser.WithLocation(err, cmd.Location())
		}
	}()
	if cmd.Action != nil {
		if strings.EqualFold(*cmd.Action, "call") {
			return handleFunctionCall(ctx, cmd, d, opt)
		}

		return fmt.Errorf("unsupported function action: %q", *cmd.Action)
	}
	return handleFunctionDefination(cmd, opt)
}

func handleFunctionCall(ctx context.Context, cmd converter.Function, d *dispatchState, opt dispatchOpt) error {
	var (
		function *converter.Function
		ok       bool
	)
	if function, ok = opt.functions[cmd.FuncName]; !ok {
		return fmt.Errorf("unknown function: %q", cmd.FuncName)
	}

	var funcArgs = append(function.Args, cmd.Args...)
	ds, dOpt := d.Clone(), opt.Clone()
	for _, kvp := range funcArgs {
		ds.state = ds.state.AddEnv(kvp.Key, kvp.ValueString())
	}
	for _, cmd := range function.Commands {
		cmd, err := toCommand(cmd, dOpt.allDispatchStates)
		if err != nil {
			return err
		}
		if err := dispatch(ctx, ds, cmd, dOpt); err != nil {
			return err
		}
	}

	copt := []llb.ConstraintsOpt{
		llb.WithCaps(*dOpt.llbCaps),
		llb.WithCustomNamef("FUNC CALL %s", cmd.FuncName),
	}

	if opt.llbCaps.Supports(pb.CapMergeOp) == nil {
		d.state = llb.Merge([]llb.State{d.state, llb.Diff(d.state, ds.state , copt...)})
	} else {
		d.state = d.state.File(llb.Copy(ds.state, "/", "/"), copt...)
	}
	return nil
}

func handleFunctionDefination(cmd converter.Function, opt dispatchOpt) error {
	opt.functions[cmd.FuncName] = &cmd
	return nil
}
