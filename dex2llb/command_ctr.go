package dex2llb

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/pkg/errors"
)

func dispatchCtr(ctx context.Context, d *dispatchState, cmd converter.CommandConatainer, opt dispatchOpt) (err error) {
	st := d.state
	if cmd.From != "" {
		index, err := strconv.Atoi(cmd.From)
		if err != nil {
			stn, ok := opt.allDispatchStates.findStateByName(cmd.From)
			if !ok {
				st = llb.Image(cmd.From)
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
		return parser.WithLocation(err, cmd.Location())
	}

	for _, cmd := range cmd.Commands {
		switch cmd := cmd.(type) {
		case *converter.CommandProcess:
			cmd.Result = res
			dClone, optClone := d.Clone(), opt.Clone()
			cmd.FROM = st
			if err, ok := handleProc(ctx, dClone, cmd, optClone); err != nil {
				if !ok {
					return parser.WithLocation(fmt.Errorf("failed to start [CTR] process: %s", strings.Join(cmd.RUN.CmdLine, " ")), cmd.Location())
				}
				return parser.WithLocation(err, cmd.Location())
			}
		case *converter.ConditionIfElse:
			conds := []converter.Command{cmd.ConditionIF.Condition}
			for _, elseCond := range cmd.ConditionElse {
				conds = append(conds, elseCond.Condition)
			}

			for _, c := range conds {
				if c, ok := c.(*converter.CommandProcess); ok {
					c.Result = res
					c.FROM = st
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

func handleProc(ctx context.Context, d *dispatchState, cmd *converter.CommandProcess, opt dispatchOpt) (err error, ctrStarted bool) {
	if cmd.Result == nil {
		return fmt.Errorf("[PROC] command not supported outside [CTR] command"), ctrStarted
	}

	var (
		stdout = bytes.NewBuffer(nil)
		stderr = bytes.NewBuffer(nil)
	)

	st := d.state.Output()
	d.state = cmd.FROM
	defer func() {
		d.state = llb.NewState(st)
		d.state = d.state.
			AddEnv("STDOUT", stdout.String()).
			AddEnv("STDERR", stderr.String())
	}()
	dc, err := toCommand(cmd.RUN, opt.allDispatchStates)
	if err != nil {
		return err, ctrStarted
	}
	err = dispatchRun(d, &cmd.RUN, opt.proxyEnv, dc.sources, opt)
	if err != nil {
		return err, ctrStarted
	}

	def, err := d.state.Marshal(ctx)
	if err != nil {
		return err, ctrStarted
	}

	var execop *execOp
	for i := len(def.Def) - 1; i >= 0; i-- {
		def := def.Def[i]
		var pop pb.Op
		if err := pop.UnmarshalVT(def); err != nil {
			return err, ctrStarted
		}
		if execop = solveOp(&pop); execop != nil {
			break
		}
	}

	if execop == nil {
		return parser.WithLocation(errors.New("no [PROC] statement found"), cmd.Location()), ctrStarted
	}

	ctr, err := createContainer(ctx, opt.solver.Client(), execop, cmd.Result)
	if err != nil {
		return err, ctrStarted
	}

	err = startProcess(ctx, ctr, cmd.TimeOut, *execop, func() error {
		return nil
	}, &nopCloser{stdout}, &nopCloser{stderr})
	if err != nil {
		return parser.WithLocation(fmt.Errorf("%s: %w", stderr.String(), err), cmd.Location()), true
	}

	return nil, true
}
