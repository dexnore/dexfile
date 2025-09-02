package dex2llb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/solver/pb"
)

type execOp struct {
	Exec        *pb.ExecOp
	Inputs      []*pb.Input
	Platform    *pb.Platform
	Constraints *pb.WorkerConstraints
}

func solveOp(baseOp *pb.Op) *execOp {
	switch op := baseOp.Op.(type) {
	case *pb.Op_Exec:
		return &execOp{
			Exec:        op.Exec,
			Inputs:      baseOp.Inputs,
			Platform:    baseOp.Platform,
			Constraints: baseOp.Constraints,
		}
	}
	return nil
}

func formatDuration(dur time.Duration) string {
	switch {
	case dur > time.Hour:
		return fmt.Sprintf("%d hours", dur/time.Hour)
	case dur > time.Minute:
		return fmt.Sprintf("%d minutes", dur/time.Minute)
	default:
		return fmt.Sprintf("%d seconds", dur/time.Second)
	}
}

func convertMounts(mounts []*pb.Mount) (cm []gwclient.Mount) {
	for _, m := range mounts {
		mnt := gwclient.Mount{
			Dest:      m.Dest,
			ResultID:  m.ResultID,
			Selector:  m.Selector,
			Ref:       nil, // Set this appropriately if you have a reference
			Readonly:  m.Readonly,
			MountType: m.MountType,
		}
		if m.CacheOpt != nil {
			mnt.CacheOpt = m.CacheOpt.CloneVT()
		}

		if m.SecretOpt != nil {
			mnt.SecretOpt = m.SecretOpt.CloneVT()
		}

		if m.SSHOpt != nil {
			mnt.SSHOpt = m.SSHOpt.CloneVT()
		}
		cm = append(cm, mnt)
	}
	return cm
}

type nopCloser struct {
	*bytes.Buffer
}

func (wc *nopCloser) Close() error {
	return nil
}

func createContainer(ctx context.Context, c gwclient.Client, execop *execOp, ref gwclient.Reference) (gwclient.Container, error) {
	if execop == nil {
		return nil, errors.New("internal error: no RUN instruction found")
	}

	if execop.Exec == nil {
		execop.Exec = &pb.ExecOp{}
	}

	if execop.Exec.Meta == nil {
		execop.Exec.Meta = &pb.Meta{}
	}

	var platform pb.Platform
	if execop.Platform != nil {
		platform = *execop.Platform.CloneVT()
	}

	var constraints pb.WorkerConstraints
	if execop.Constraints != nil {
		constraints = *execop.Constraints.CloneVT()
	}

	ctrReq := gwclient.NewContainerRequest{
		Mounts: append(
			convertMounts(execop.Exec.Mounts),
			gwclient.Mount{
				Dest:      "/",
				MountType: pb.MountType_BIND,
				Ref:       ref,
			},
		),
		Hostname:    execop.Exec.Meta.GetHostname(),
		NetMode:     execop.Exec.GetNetwork(),
		ExtraHosts:  slices.Clone(execop.Exec.Meta.GetExtraHosts()),
		Platform:    &platform,
		Constraints: &constraints,
	}

	return c.NewContainer(ctx, ctrReq)
}

func startContainer(ctx context.Context, ctr gwclient.Container, execop *pb.ExecOp, stdout, stderr io.WriteCloser) (gwclient.ContainerProcess, error) {
	if execop == nil {
		return nil, fmt.Errorf("failed to create ctr process %+v", execop)
		// return ctr.Start(ctx, client.StartRequest{})
	}
	startReq := gwclient.StartRequest{
		Args:                      execop.Meta.Args,
		Env:                       execop.Meta.Env,
		SecretEnv:                 execop.Secretenv,
		User:                      execop.Meta.User,
		Cwd:                       execop.Meta.Cwd,
		Tty:                       false, // default
		Stdin:                     nil,   // default
		Stdout:                    stdout,
		Stderr:                    stderr,
		SecurityMode:              execop.Security,
		RemoveMountStubsRecursive: execop.Meta.RemoveMountStubsRecursive,
	}

	return ctr.Start(ctx, startReq)
}

type WriteCloseStringer interface {
	io.WriteCloser
	String() string
}

func startProcess(ctx context.Context, ctr gwclient.Container, timeout *time.Duration, execop execOp, handleCond func() (bool, error), stdout, stderr WriteCloseStringer) (retErr, buildCmd bool, err error) {
	defer func() {
		if err == nil && handleCond != nil {
			retErr = true
			var delCtr bool
			delCtr, err = handleCond()
			if delCtr {
				buildCmd = true
				ctr.Release(ctx)
			}
		}
	}()
	dur := 10 * time.Minute
	if timeout != nil {
		dur = *timeout
	}

	pidCtx, cancel := context.WithTimeoutCause(ctx, dur, fmt.Errorf("timeout: conditional instruction exceeded %s. Increase the --timeout if necessary", formatDuration(dur)))
	defer cancel()
	var pid gwclient.ContainerProcess
	pid, err = startContainer(pidCtx, ctr, execop.Exec, stdout, stderr)
	if err != nil {
		return false, false, err
	}

	if pid == nil {
		return false, false, fmt.Errorf("pid is nil")
	}
	err = pid.Wait()
	if err != nil {
		err = fmt.Errorf("container process failed: %w\n%s", err, stderr)
	}

	return false, false, err
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
		i int = 0
		block converter.Command = cmd.ConditionIF
		ifElseID = identity.NewID()
		localCopts = []llb.ConstraintsOpt{
			llb.WithCaps(*opt.llbCaps), 
			llb.ProgressGroup(ifElseID, "IF/ELSE ==> "+cmd.String(), false),
		}
		LocalCopts = append(copts, localCopts...)
	)

forloop:
	for i, block = range conds {
		if block == nil && i > 0 { // else condition (not 'else if')
			return exec(cmd.ConditionElse[i-1].Commands, localCopts...)
		}

		ds := d.Clone()
		dOpt, err := opt.Clone()
		if err != nil {
			return false, err
		}
		switch cond := block.(type) {
		case *converter.RunCommand:
			dc, err := toCommand(cond, dOpt.allDispatchStates)
			if err != nil {
				return false, err
			}
			if _, err = dispatch(ctx, ds, dc, dOpt, localCopts...); err != nil {
				return false, err
			}
		case *converter.CommandExec:
			def, err := ds.state.Marshal(ctx)
			if err != nil {
				return false, err
			}

			res, err := opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
				Evaluate:     true,
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
		case *converter.CommandProcess:
			err, ok := handleProc(ctx, ds, cond, dOpt)
			if !ok {
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
			bs, err := dispatchBuild(ctx, *cond, opt, localCopts...)
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

		def, err := ds.state.Marshal(ctx)
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
			return false, parser.WithLocation(errors.New("no conditional statement found"), block.Location())
		}

		ddef, err := d.state.Marshal(ctx)
		if err != nil {
			return false, err
		}

		res, err := opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
			Evaluate:     true,
			Definition:   ddef.ToPB(),
			CacheImports: opt.solver.Client().Config().CacheImports,
		})
		if err != nil {
			return false, parser.WithLocation(fmt.Errorf("failed to marshal state: %w", err), cmd.Location())
		}

		ctr, ctrErr = createContainer(ctx, dOpt.solver.Client(), execop, res.Ref)
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
			} else {
				return exec(cmd.ConditionElse[i-1].Commands, localCopts...)
			}
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
		returnErr, breakCmd, err = startProcess(ctx, ctr, timeout, *execop, func() (bool, error) {
			d.state = d.state.
				AddEnv("STDOUT", stripNewlineSuffix(stdout.String())[0]).
				AddEnv("STDERR", stripNewlineSuffix(stderr.String())[0])
			return exec(conditionalCommands, LocalCopts...)
		}, &nopCloser{stdout}, &nopCloser{stderr})
		if returnErr {
			return breakCmd, err
		}
		errs = errors.Join(errors.New(stderr.String()), parser.WithLocation(err, block.Location()), errs)
		if breakCmd {
			return true, nil
		}
		continue forloop
	}

	if errs == nil || conds[len(conds) - 1] != nil { // NOTE: if no 'else' condition => skip error
		return false, nil
	}

	return false, fmt.Errorf("all conditions failed: %w", errs)
}

func stripNewlineSuffix(s string) []string {
    if strings.HasSuffix(s, "\n") {
        return strings.Split(s, "\n")
    }
    return []string{s}
}
