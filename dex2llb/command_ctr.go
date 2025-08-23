package dex2llb

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/pkg/errors"
)

var (
	ARG_STDOUT = dexfile.ScopedVariable("STDOUT")
	ARG_STDERR = dexfile.ScopedVariable("STDERR")
)

func dispatchCtr(ctx context.Context, d *dispatchState, ctr converter.CommandConatainer, opt dispatchOpt) (err error) {
	st := d.state
	if ctr.From != "" {
		index, err := strconv.Atoi(ctr.From)
		if err != nil {
			stn, ok := opt.allDispatchStates.findStateByName(ctr.From)
			if !ok {
				st = llb.Image(ctr.From)
			} else {
				st = stn.state
			}
		} else {
			stn, err := opt.allDispatchStates.findStateByIndex(index)
			if err != nil {
				return err
			}
			st = stn.state
		}
	}
	cwd, err := st.GetDir(ctx)
	if err != nil || cwd == "" {
		st = st.Dir("/")
	}

	def, err := st.Marshal(ctx)
	if err != nil {
		return err
	}

	res, err := opt.solver.Client().Solve(ctx, client.SolveRequest{
		Evaluate:     true,
		Definition:   def.ToPB(),
		CacheImports: opt.solver.Client().Config().CacheImports,
	})
	if err != nil {
		return parser.WithLocation(err, ctr.Location())
	}

	ctr.Result = res
	ctr.State = &st

	for _, cmd := range ctr.Commands {
		switch cmd := cmd.(type) {
		case *converter.CommandProcess:
			cmd.InContainer = *ctr.Clone()
			dClone, optClone := d.Clone(), opt.Clone()
			if err, ok := handleProc(ctx, dClone, cmd, optClone); err != nil {
				if !ok {
					return parser.WithLocation(fmt.Errorf("failed to start [CTR] process: %s\n%w", strings.Join(cmd.RUN.CmdLine, " "), err), cmd.Location())
				}
				return err
			}
			stdout, _ := dClone.state.Value(ctx, ARG_STDOUT)
			stderr, _ := dClone.state.Value(ctx, ARG_STDERR)
			d.state = d.state.WithValue(ARG_STDOUT, stdout).WithValue(ARG_STDERR, stderr)
		case *converter.ConditionIfElse:
			conds := []converter.Command{cmd.ConditionIF.Condition}
			for _, elseCond := range cmd.ConditionElse {
				conds = append(conds, elseCond.Condition)
			}

			for _, c := range conds {
				if c, ok := c.(*converter.CommandProcess); ok {
					c.InContainer = *ctr.Clone()
				}
			}
			dc, err := toCommand(cmd, opt.allDispatchStates)
			if err != nil {
				return parser.WithLocation(err, cmd.Location())
			}
			if err := dispatch(ctx, d, dc, opt); err != nil {
				return parser.WithLocation(err, dc.Location())
			}
		default:
			dc, err := toCommand(cmd, opt.allDispatchStates)
			if err != nil {
				return parser.WithLocation(err, cmd.Location())
			}
			if err := dispatch(ctx, d, dc, opt); err != nil {
				return parser.WithLocation(err, dc.Location())
			}
		}
	}

	return nil
}

func handleProc(ctx context.Context, d *dispatchState, cmd *converter.CommandProcess, opt dispatchOpt) (err error, false bool) {
	ctr := cmd.InContainer
	if cmd.From != "" {
		fromCtr, ok := cmd.FindContainer(cmd.From)
		if !ok {
			return parser.WithLocation(fmt.Errorf("no container found with name: %s", cmd.From), cmd.RUN.Location()), false
		}
		ctr = *fromCtr.Clone()
	}
	if ctr.Result == nil || ctr.State == nil {
		return fmt.Errorf("[PROC] command not supported outside [CTR] command"), false
	}

	var (
		stdout = bytes.NewBuffer(nil)
		stderr = bytes.NewBuffer(nil)
	)

	st := d.state
	d.state = *ctr.State
	defer func() {
		*ctr.State = llb.NewState(d.state.Output())
		d.state = st.
			WithValue(ARG_STDOUT, stdout.String()).
			WithValue(ARG_STDERR, stderr.String())
	}()
	dc, err := toCommand(cmd.RUN, opt.allDispatchStates)
	if err != nil {
		return err, false
	}
	err = dispatchRun(d, &cmd.RUN, opt.proxyEnv, dc.sources, opt)
	if err != nil {
		return err, false
	}

	def, err := d.state.Marshal(ctx)
	if err != nil {
		return err, false
	}

	var execop *execOp
	for i := len(def.Def) - 1; i >= 0; i-- {
		def := def.Def[i]
		var pop pb.Op
		if err := pop.UnmarshalVT(def); err != nil {
			return err, false
		}
		if execop = solveOp(&pop); execop != nil {
			break
		}
	}

	if execop == nil {
		return parser.WithLocation(errors.New("no [PROC] statement found"), cmd.RUN.Location()), false
	}

	gwctr, err := createContainer(ctx, opt.solver.Client(), execop, ctr.Result.Ref)
	if err != nil {
		return err, false
	}

	defer func() {
		gwctr.Release(ctx)
	}()

	var retErr bool
	err, retErr = startProcess(ctx, gwctr, cmd.TimeOut, *execop, func() error {
		return nil
	}, &nopCloser{stdout}, &nopCloser{stderr})
	if retErr && err != nil {
		return parser.WithLocation(fmt.Errorf("%s: %w", stderr.String(), err), cmd.RUN.Location()), true
	}

	return err, true
}
