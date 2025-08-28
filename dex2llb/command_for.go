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
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/solver/pb"
)

func handleForLoop(ctx context.Context, d *dispatchState, cmd converter.CommandFor, exec func([]converter.Command, ...llb.ConstraintsOpt) error, opt dispatchOpt, copts ...llb.ConstraintsOpt) (err error) {
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
	)

	defer func() {
		if ctr == nil {
			return
		}
		ctr.Release(ctx)
	}()

	forID := identity.NewID()
	localCopts := []llb.ConstraintsOpt{
		llb.WithCaps(*opt.llbCaps),
		llb.ProgressGroup(forID, fmt.Sprintf("FOR %+v", cmd.EXEC), false),
	}
	LocalCopts := append(copts, localCopts...)
	ds, dOpt, isProc := d.Clone(), opt.Clone(), false
	switch exec := cmd.EXEC.(type) {
	case *converter.CommandExec:
		exec.Result = res
		ic, err := toCommand(exec, dOpt.allDispatchStates)
		if err != nil {
			return err
		}
		err = dispatch(ctx, ds, ic, dOpt, LocalCopts...)
		if err != nil {
			return parser.WithLocation(fmt.Errorf("exec command error: %w", err), exec.Location())
		}
	case *converter.RunCommand:
		dc, err := toCommand(exec, dOpt.allDispatchStates)
		if err != nil {
			return parser.WithLocation(fmt.Errorf("toCommand: %w", err), exec.Location())
		}
		if err = dispatch(ctx, ds, dc, dOpt, LocalCopts...); err != nil {
			return parser.WithLocation(fmt.Errorf("run command: %s", err), exec.Location())
		}
	case *converter.CommandProcess:
		if err, ok := handleProc(ctx, ds, exec, dOpt); err != nil {
			if !ok {
				return parser.WithLocation(fmt.Errorf("process command: %s", err), exec.Location())
			}
			return err
		}
		isProc = true
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

	var (
		stdout = bytes.NewBuffer(nil)
		stderr = bytes.NewBuffer(nil)
		returnErr bool
	)
	err, returnErr = startProcess(ctx, ctr, cmd.TimeOut, *execop, func() error {
		return nil
	}, &nopCloser{stdout}, &nopCloser{stderr})
	if err != nil {
		if returnErr {
			return parser.WithLocation(fmt.Errorf("%s: %w", stderr.String(), err), cmd.Location())
		}
		return err
	}

	if cmd.Regex.Action == "" {
		cmd.Regex.Action = "\n"
	}

	defaultAs, _ := d.state.Value(ctx, dexfile.ScopedVariable(cmd.As))
	if isProc {
		defaultSTDOUT, _ := ds.state.Value(ctx, dexfile.ScopedVariable("STDOUT"))
		stdout = bytes.NewBuffer([]byte(defaultSTDOUT.(string)))
	}
	defer func() {
		d.state = d.state.WithValue(dexfile.ScopedVariable(cmd.As), defaultAs)
	}()
	delim, err := regexp.Compile(cmd.Regex.Regex)
	if err == nil {
		var regexOutput []string
		switch stdout := stripNewlineSuffix(stdout.String())[0]; cmd.Regex.Action {
		case converter.ActionRegexSplit:
			regexOutput = delim.Split(stdout, -1)
		case converter.ActionRegexMatch:
			regexOutput = delim.FindAllString(stdout, -1)
		default:
			return fmt.Errorf("unsupported regex action: %s", cmd.Regex.Action)
		}
		for i, dv := range regexOutput {
			d.state = d.state.
				WithValue(dexfile.ScopedVariable(cmd.As), dv).
				WithValue(dexfile.ScopedVariable("INDEX"), i)
			if err := exec(cmd.Commands, append(LocalCopts, llb.WithCustomNamef("FOR [%s=%s]", cmd.As, dv))...); err != nil {
				return err
			}
		}
	}

	return err
}
