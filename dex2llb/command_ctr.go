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
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/solver/pb"
	"github.com/pkg/errors"
)

var (
	ARG_STDOUT = dexfile.ScopedVariable("STDOUT")
	ARG_STDERR = dexfile.ScopedVariable("STDERR")
)

func dispatchCtr(ctx context.Context, d *dispatchState, ctr converter.CommandConatainer, opt dispatchOpt, copts ...llb.ConstraintsOpt) (breakCmd bool, err error) {
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
				return false, err
			}
			st = stn.state
		}
	}
	ctrID := identity.NewID()
	localCopts := []llb.ConstraintsOpt{
		llb.WithCaps(*opt.llbCaps),
		llb.ProgressGroup(ctrID, ctr.String(), false),
	}
	LocalCopts := append(copts, localCopts...)

	dClone := d.Clone()
	dClone.state = st
	optClone, err := opt.Clone()
	if err != nil {
		return false, err
	}

	c, err := toCommand(ctr, opt.allDispatchStates)
	if err != nil {
		return false, err
	}

	_, err = dispatchMetaExecOp(dClone, &ctr, ctr.String(), []string{"fake", "cmd"}, optClone.proxyEnv, c.sources, optClone, make([]llb.RunOption, 0), LocalCopts...)
	if err != nil {
		return false, err
	}

	def, err := dClone.state.Marshal(ctx, append(LocalCopts, llb.WithCustomNamef("creating custom container [%s]", ctr.From))...)
	if err != nil {
		return false, err
	}

	var execop *execOp
	for i := len(def.Def) - 1; i >= 0; i-- {
		def := def.Def[i]
		var pop pb.Op
		if err := pop.UnmarshalVT(def); err != nil {
			return false, err
		}
		if execop = solveOp(&pop); execop != nil {
			break
		}
	}

	if execop == nil {
		return false, parser.WithLocation(errors.New("unable to create container"), ctr.Location())
	}

	gwctr, err := createContainer(ctx, opt.solver.Client(), execop, ctr.Result.Ref)
	if err != nil {
		return false, err
	}

	defer gwctr.Release(ctx)

	def, err = st.Marshal(ctx, append(LocalCopts, llb.WithCustomNamef("retriving container state [%s]", ctr.From))...)
	if err != nil {
		return false, err
	}

	res, err := opt.solver.Client().Solve(ctx, client.SolveRequest{
		Evaluate:     true,
		Definition:   def.ToPB(),
		CacheImports: opt.solver.Client().Config().CacheImports,
	})
	if err != nil {
		return false, parser.WithLocation(err, ctr.Location())
	}

	ctr.Container = gwctr
	ctr.Result = res
	ctr.State = dClone.state

	for _, cmd := range ctr.Commands {
		switch cmd := cmd.(type) {
		case *converter.CommandProcess:
			cmd.InContainer = *ctr.Clone()
			dClone := d.Clone()
			optClone, err := opt.Clone()
			if err != nil {
				return false, err
			}
			if ok, err := handleProc(ctx, dClone, cmd, optClone); err != nil {
				if !ok {
					return false, parser.WithLocation(fmt.Errorf("failed to start [CTR] process: %s\n%w", strings.Join(cmd.RUN.CmdLine, " "), err), cmd.Location())
				}
				return false, err
			}
			stdout, _ := dClone.state.Value(ctx, ARG_STDOUT)
			stderr, _ := dClone.state.Value(ctx, ARG_STDERR)
			d.state = d.state.WithValue(ARG_STDOUT, stdout).WithValue(ARG_STDERR, stderr)
		case *converter.ConditionIfElse:
			conds := []converter.Command{cmd.ConditionIF.Condition}
			for _, elseCond := range cmd.ConditionElse {
				for _, c := range elseCond.Commands {
					if c, ok := c.(*converter.CommandProcess); ok {
						c.InContainer = *ctr.Clone()
					}
				}
				conds = append(conds, elseCond.Condition)
			}

			for _, c := range conds {
				if c, ok := c.(*converter.CommandProcess); ok {
					c.InContainer = *ctr.Clone()
				}
			}

			for _, ifcmd := range cmd.ConditionIF.Commands {
				if c, ok := ifcmd.(*converter.CommandProcess); ok {
					c.InContainer = *ctr.Clone()
				}
			}

			dc, err := toCommand(cmd, opt.allDispatchStates)
			if err != nil {
				return false, parser.WithLocation(err, cmd.Location())
			}
			if breakCmd, err = dispatch(ctx, d, dc, opt, LocalCopts...); err != nil {
				return breakCmd, parser.WithLocation(err, dc.Location())
			}
			if breakCmd {
				return true, nil
			}
		case *converter.CommandFor:
			if c, ok := cmd.EXEC.(*converter.CommandProcess); ok {
				c.InContainer = *ctr.Clone()
			}

			for _, c := range cmd.Commands {
				if c, ok := c.(*converter.CommandProcess); ok {
					c.InContainer = *ctr.Clone()
				}
			}
			dc, err := toCommand(cmd, opt.allDispatchStates)
			if err != nil {
				return false, parser.WithLocation(err, cmd.Location())
			}
			if breakCmd, err = dispatch(ctx, d, dc, opt, LocalCopts...); err != nil {
				return breakCmd, parser.WithLocation(err, dc.Location())
			}
			if breakCmd {
				return true, nil
			}
		case *converter.Function:
			for _, c := range cmd.Commands {
				if c, ok := c.(*converter.CommandProcess); ok {
					c.InContainer = *ctr.Clone()
				}
			}
		default:
			dc, err := toCommand(cmd, opt.allDispatchStates)
			if err != nil {
				return false, parser.WithLocation(err, cmd.Location())
			}
			if breakCmd, err = dispatch(ctx, d, dc, opt, LocalCopts...); err != nil {
				return breakCmd, parser.WithLocation(err, dc.Location())
			}
			if breakCmd {
				return true, nil
			}
		}
	}

	return false, nil
}

func handleProc(ctx context.Context, d *dispatchState, cmd *converter.CommandProcess, opt dispatchOpt) (false bool, err error) {
	ctr := cmd.InContainer
	if cmd.From != "" {
		fromCtr, ok := cmd.FindContainer(cmd.From)
		if !ok {
			return false, parser.WithLocation(fmt.Errorf("no container found with name: %s", cmd.From), cmd.RUN.Location())
		}
		ctr = *fromCtr.Clone()
	}
	if ctr.Result == nil || ctr.Container == nil {
		return false, fmt.Errorf("[PROC] command not supported outside [CTR] command")
	}

	var (
		stdout = bytes.NewBuffer(nil)
		stderr = bytes.NewBuffer(nil)
	)

	st := d.state
	d.state = ctr.State
	defer func() {
		ctr.State = d.state
		d.state = st.
			WithValue(ARG_STDOUT, stripNewlineSuffix(stdout.String())[0]).
			WithValue(ARG_STDERR, stripNewlineSuffix(stderr.String())[0])
	}()
	err = cmd.RUN.Expand(func(word string) (string, error) {
		env := getEnv(d.state)
		newword, unmatched, err := opt.shlex.ProcessWord(word, env)
		reportUnmatchedVariables(cmd, d.buildArgs, env, unmatched, &opt)
		return newword, err
	})
	if err != nil {
		return false, err
	}
	dc, err := toCommand(cmd.RUN, opt.allDispatchStates)
	if err != nil {
		return false, err
	}
	err = dispatchRun(d, &cmd.RUN, opt.proxyEnv, dc.sources, opt, llb.WithCustomNamef("%s", cmd.String()))
	if err != nil {
		return false, err
	}

	def, err := d.state.Marshal(ctx)
	if err != nil {
		return false, err
	}

	var execop *execOp
	for i := len(def.Def) - 1; i >= 0; i-- {
		def := def.Def[i]
		var pop pb.Op
		if err := pop.UnmarshalVT(def); err != nil {
			return false, err
		}
		if execop = solveOp(&pop); execop != nil {
			break
		}
	}

	if execop == nil {
		return false, parser.WithLocation(errors.New("no [PROC] statement found"), cmd.RUN.Location())
	}

	var retErr bool
	retErr, _, err = startProcess(ctx, ctr.Container, cmd.TimeOut, *execop, func() (bool, error) {
		return false, nil
	}, &nopCloser{stdout}, &nopCloser{stderr})
	if retErr && err != nil {
		return true, parser.WithLocation(fmt.Errorf("%s: %w", stderr.String(), err), cmd.RUN.Location())
	}

	return true, err
}
