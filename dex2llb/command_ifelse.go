package dex2llb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dexnore/dexfile/dex2llb/internal"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/identity"
)

type nopCloser struct {
	*bytes.Buffer
}

func (wc *nopCloser) Close() error {
	return nil
}

type WriteCloseStringer interface {
	io.WriteCloser
	String() string
}

func handleIfElse(ctx context.Context, d *dispatchState, cmd converter.ConditionIfElse, exec func([]converter.Command, ...llb.ConstraintsOpt) (bool, error), opt dispatchOpt, copts ...llb.ConstraintsOpt) (breakCmd bool, err error) {
	var errs error
	if cmd.ConditionIF == nil || cmd.ConditionIF.Condition == nil {
		return false, errors.New("'if' condition cannot be nil")
	}

	conds := []converter.Command{cmd.ConditionIF.Condition}
	for _, elseCond := range cmd.ConditionElse {
		conds = append(conds, elseCond.Condition)
	}

	var (
		ctr    gwclient.Container
		ctrErr error
	)
	defer func() {
		if ctr == nil {
			return
		}
		ctr.Release(ctx)
	}()

	var (
		i          int               = 0
		block      converter.Command = cmd.ConditionIF
		ifElseID                     = identity.NewID()
		localCopts                   = []llb.ConstraintsOpt{
			llb.WithCaps(*opt.llbCaps),
			llb.ProgressGroup(ifElseID, "IF/ELSE ==> "+cmd.String(), false),
		}
		LocalCopts = append(copts, localCopts...)
	)

	var (
		prevStdout = bytes.NewBuffer(nil)
		prevStderr = bytes.NewBuffer(nil)
	)

forloop:
	for i, block = range conds {
		if block == nil && i > 0 { // else condition (not 'else if')
			d.state = d.state.
				AddEnv("STDOUT", stripNewlineSuffix(prevStdout.String())[0]).
				AddEnv("STDERR", stripNewlineSuffix(prevStderr.String())[0])
			return exec(cmd.ConditionElse[i-1].Commands, localCopts...)
		}

		ds := d.Clone()
		dOpt, err := opt.Clone()
		if err != nil {
			return false, err
		}
		var execop *internal.ExecOp
		switch cond := block.(type) {
		case *converter.RunCommand:
			dc, err := toCommand(cond, dOpt.allDispatchStates)
			if err != nil {
				return false, err
			}
			if _, err = dispatch(ctx, ds, dc, dOpt, localCopts...); err != nil {
				return false, err
			}

			def, err := ds.state.Marshal(ctx)
			if err != nil {
				return false, err
			}

			execop, err = internal.MarshalToExecOp(def)
			if err != nil {
				return false, err
			}

			if execop == nil {
				return false, parser.WithLocation(errors.New("no conditional statement found"), block.Location())
			}

			ddef, err := d.state.Marshal(ctx)
			if err != nil {
				return false, err
			}

			res, err := opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
				Definition:   ddef.ToPB(),
				CacheImports: opt.solver.Client().Config().CacheImports,
			})
			if err != nil {
				return false, parser.WithLocation(fmt.Errorf("failed to marshal state: %w", err), cmd.Location())
			}

			ctrMounts, err := mountsForContainer(ctx, cond, execop, dc.sources, res, ds, dOpt)
			if err != nil {
				return false, err
			}
			ctr, ctrErr = internal.CreateContainer(ctx, dOpt.solver.Client(), execop, ctrMounts)
			if ctrErr != nil {
				return false, parser.WithLocation(ctrErr, block.Location())
			}

			if execop.Exec != nil && execop.Exec.CdiDevices != nil {
				_, err := ds.opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
					Evaluate:     true,
					Definition:   def.ToPB(),
					CacheImports: dOpt.solver.Client().Config().CacheImports,
				})
				if err != nil {
					errs = errors.Join(errs, parser.WithLocation(err, block.Location()))
					continue forloop
				}

				if i == 0 {
					return exec(cmd.ConditionIF.Commands, localCopts...)
				}
				return exec(cmd.ConditionElse[i-1].Commands, localCopts...)
			}
		case *converter.CommandExec:
			def, err := ds.state.Marshal(ctx)
			if err != nil {
				return false, err
			}

			res, err := opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
				Definition:   def.ToPB(),
				CacheImports: dOpt.solver.Client().Config().CacheImports,
			})
			if err != nil {
				return false, parser.WithLocation(err, cmd.Location())
			}

			cond.Result = res
			ic, err := toCommand(cond, dOpt.allDispatchStates)
			if err != nil {
				return false, err
			}
			_, err = dispatch(ctx, ds, ic, dOpt, localCopts...)
			if err != nil {
				return false, err
			}

			def, err = ds.state.Marshal(ctx)
			if err != nil {
				return false, err
			}

			res, err = opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
				Evaluate:     true,
				Definition:   def.ToPB(),
				CacheImports: opt.solver.Client().Config().CacheImports,
			})
			if res == nil {
				return false, parser.WithLocation(fmt.Errorf("failed to solve EXEC: %w", err), block.Location())
			}
			err = nil

			execop, err = internal.MarshalToExecOp(def)
			if err != nil {
				return false, err
			}

			if execop == nil {
				return false, parser.WithLocation(errors.New("no conditional statement found"), block.Location())
			}

			ctrMounts, err := mountsForContainer(ctx, cond.RUN, execop, ic.sources, res, ds, dOpt)
			if err != nil {
				return false, err
			}
			ctr, ctrErr = internal.CreateContainer(ctx, dOpt.solver.Client(), execop, ctrMounts)
			if ctrErr != nil {
				return false, parser.WithLocation(ctrErr, block.Location())
			}

			if execop.Exec != nil && execop.Exec.CdiDevices != nil {
				_, err := ds.opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
					Evaluate:     true,
					Definition:   def.ToPB(),
					CacheImports: dOpt.solver.Client().Config().CacheImports,
				})
				if err != nil {
					errs = errors.Join(errs, parser.WithLocation(err, block.Location()))
					continue forloop
				}

				if i == 0 {
					return exec(cmd.ConditionIF.Commands, localCopts...)
				}
				return exec(cmd.ConditionElse[i-1].Commands, localCopts...)
			}
		case *converter.CommandProcess:
			stdout, stderr, err := handleProc(ctx, ds, cond, dOpt)
			if stdout.String() == "" && stderr.String() == "" {
				if err == nil {
					err = fmt.Errorf("unable to start [PROC]")
				}
				return false, parser.WithLocation(err, cond.Location())
			}

			if err != nil {
				errs = errors.Join(parser.WithLocation(err, cond.Location()), errs)
				continue forloop
			}

			if i == 0 {
				return exec(cmd.ConditionIF.Commands, localCopts...)
			} else {
				return exec(cmd.ConditionElse[i-1].Commands, localCopts...)
			}
		case *converter.CommandBuild:
			dOpt, err := opt.Clone()
			if err != nil {
				return false, err
			}
			bs, err := dispatchBuild(ctx, *cond, dOpt, localCopts...)
			if err != nil {
				return false, err
			}

			def, err := bs.state.Marshal(ctx)
			if err != nil {
				return false, err
			}

			_, err = opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
				Evaluate:     true,
				Definition:   def.ToPB(),
				CacheImports: opt.solver.Client().Config().CacheImports,
			})
			if err != nil {
				errs = errors.Join(parser.WithLocation(err, cond.Location()), errs)
				continue forloop
			}

			if i == 0 {
				return exec(cmd.ConditionIF.Commands, localCopts...)
			} else {
				return exec(cmd.ConditionElse[i-1].Commands, localCopts...)
			}
		default:
			return false, fmt.Errorf("unsupported conditional subcommand: %s", cond.Name())
		}

		var (
			stdout = bytes.NewBuffer(nil)
			stderr = bytes.NewBuffer(nil)
		)

		var timeout *time.Duration
		var conditionalCommands []converter.Command
		if i == 0 {
			timeout, conditionalCommands = cmd.ConditionIF.TimeOut, cmd.ConditionIF.Commands
		} else {
			timeout, conditionalCommands = cmd.ConditionElse[i-1].TimeOut, cmd.ConditionElse[i-1].Commands
		}

		var returnErr bool
		returnErr, breakCmd, err = internal.StartProcess(ctx, ctr, timeout, *execop, func() (bool, error) {
			d.state = d.state.
				AddEnv("STDOUT", stripNewlineSuffix(stdout.String())[0]).
				AddEnv("STDERR", stripNewlineSuffix(stderr.String())[0])
			return exec(conditionalCommands, LocalCopts...)
		}, &nopCloser{stdout}, &nopCloser{stderr})
		if stdout != nil {
			prevStdout.Write(stdout.Bytes())
		}
		if stderr != nil {
			prevStderr.Write(stderr.Bytes())
		}
		if returnErr {
			return breakCmd, err
		}
		errs = errors.Join(errors.New(stderr.String()), parser.WithLocation(err, block.Location()), errs)
		if breakCmd {
			return true, nil
		}
		continue forloop
	}

	return false, nil
}

func stripNewlineSuffix(s string) []string {
	if strings.HasSuffix(s, "\n") {
		return strings.Split(s, "\n")
	}
	return []string{s}
}
