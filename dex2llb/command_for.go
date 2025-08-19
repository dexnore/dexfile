package dex2llb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
)

func handleForLoop(ctx context.Context, d *dispatchState, cmd converter.CommandFor, exec func([]converter.Command, string) error, opt dispatchOpt) (err error) {
	if cmd.Action != converter.ActionForIn {
		return fmt.Errorf("unsupported 'for' action: %s", cmd.Action)
	}

	def, err := d.state.Marshal(ctx)
	if err != nil {
		return err
	}

	res, err := opt.solver.Client().Solve(ctx, client.SolveRequest{
		Evaluate:     true,
		Definition:   def.ToPB(),
		CacheImports: opt.solver.Client().Config().CacheImports,
	})
	if err != nil {
		return parser.WithLocation(fmt.Errorf("failed to start [for] loop: %w", err), cmd.Location())
	}

	var (
		ctr    client.Container
		ctrErr error
		stdout = bytes.NewBuffer(nil)
		stderr = bytes.NewBuffer(nil)
	)

	defer func() {
		if ctr == nil {
			return
		}
		if ctrErr := ctr.Release(ctx); ctrErr != nil {
			err = errors.Join(ctrErr, err)
		}
	}()

	ds, dOpt := d.Clone(), opt.Clone()
	switch exec := cmd.EXEC.(type) {
	case *converter.CommandExec:
		err = dispatchExec(ctx, ds, *exec, res, dOpt)
		if err != nil {
			return parser.WithLocation(fmt.Errorf("exec command error: %w", err), exec.Location())
		}
	case *converter.RunCommand:
		dc, err := toCommand(exec, dOpt.allDispatchStates)
		if err != nil {
			return parser.WithLocation(fmt.Errorf("toCommand: %w", err), exec.Location())
		}
		if err = dispatchRun(ds, exec, dOpt.proxyEnv, dc.sources, dOpt); err != nil {
			return parser.WithLocation(fmt.Errorf("run command: %s", err), exec.Location())
		}
	default:
		return parser.WithLocation(fmt.Errorf("unsupported [FOR] command exec: %s", exec.Name()), exec.Location())
	}

	def, err = ds.state.Marshal(ctx)
	if err != nil {
		return err
	}

	var execop *execOp
	for i := len(def.Def) - 1; i >= 0; i-- {
		def := def.Def[i]
		var pop pb.Op
		if err := pop.UnmarshalVT(def); err != nil {
			return err
		}
		if execop = solveOp(&pop); execop != nil {
			break
		}
	}

	if execop == nil {
		return parser.WithLocation(errors.New("no [FOR ... RUN] statement found"), cmd.Location())
	}

	ctr, ctrErr = createContainer(ctx, dOpt.solver.Client(), execop, res.Ref)
	if ctrErr != nil {
		return parser.WithLocation(ctrErr, cmd.Location())
	}

	err = startProcess(ctx, ctr, cmd.TimeOut, *execop, func() error {
		return nil
	}, &nopCloser{stdout}, &nopCloser{stderr})
	if err != nil {
		return parser.WithLocation(fmt.Errorf("%s: %w", stderr.String(), err), cmd.Location())
	}

	if cmd.Delim == "" {
		cmd.Delim = "\n"
	}

	defaultAs, _ := d.state.Value(ctx, dexfile.ScopedVariable(cmd.As))
	defer func() {
		d.state = d.state.WithValue(dexfile.ScopedVariable(cmd.As), defaultAs)
	}()
	delim, err := regexp.Compile(cmd.Delim)
	if err == nil {
		v := delim.FindAllString(stdout.String(), -1)
		for _, dv := range v {
			d.state = d.state.WithValue(dexfile.ScopedVariable(cmd.As), dv)
			if err := exec(cmd.Commands, dv); err != nil {
				return err
			}
		}
	}

	return err
}
