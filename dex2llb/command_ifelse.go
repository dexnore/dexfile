package dex2llb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
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

func startProcess(ctx context.Context, ctr gwclient.Container, timeout *time.Duration, execop execOp, handleCond func() error, stdout, stderr WriteCloseStringer) (err error, retErr bool) {
	defer func() {
		if err == nil && handleCond != nil {
			retErr = true
			err = handleCond()
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
		return err, false
	}

	if pid == nil {
		return fmt.Errorf("pid is nil"), false
	}
	err = pid.Wait()
	if err != nil {
		err = fmt.Errorf("container process failed: %w\n%s", err, stderr)
	}

	return err, false
}

func handleIfElse(ctx context.Context, d *dispatchState, cmd converter.ConditionIfElse, exec func([]converter.Command) error, opt dispatchOpt) (err error) {
	var errs error
	if cmd.ConditionIF == nil || cmd.ConditionIF.Condition == nil {
		return errors.New("'if' condition cannot be nil")
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

	ifElseID := identity.NewID()
	dClone := d.Clone()
	defer func() {
		if opt.llbCaps.Supports(pb.CapMergeOp) == nil {
			d.state = llb.Merge([]llb.State{d.state, llb.Diff(d.state, dClone.state)}, llb.WithCaps(*opt.llbCaps), llb.ProgressGroup(ifElseID, "IF/ELSE ==> "+cmd.String(), true))
		} else {
			d.state = d.state.File(llb.Copy(dClone.state, "/", "/"),  llb.WithCaps(*opt.llbCaps), llb.ProgressGroup(ifElseID, "IF/ELSE ==> "+cmd.String(), true))
		}
	}()

forloop:
	for i, block := range conds {
		if block == nil && i > 0 { // else condition (not 'else if')
			return exec(cmd.ConditionElse[i-1].Commands)
		}

		ds, dOpt := d.Clone(), opt.Clone()
		switch cond := block.(type) {
		case *converter.RunCommand:
			dc, err := toCommand(cond, dOpt.allDispatchStates)
			if err != nil {
				return err
			}
			if err = dispatch(ctx, ds, dc, dOpt); err != nil {
				return err
			}
		case *converter.CommandExec:
			copts := []llb.ConstraintsOpt{llb.WithCaps(*dOpt.llbCaps), llb.ProgressGroup(ifElseID, "IF/ELSE ==> " + cond.String(), true)}
			def, err := ds.state.Marshal(ctx, copts...)
			if err != nil {
				return err
			}

			res, err := opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
				Evaluate:     true,
				Definition:   def.ToPB(),
				CacheImports: dOpt.solver.Client().Config().CacheImports,
			})
			if err != nil {
				return parser.WithLocation(err, cmd.Location())
			}

			cond.Result = res
			ic, err := toCommand(cond, dOpt.allDispatchStates)
			if err != nil {
				return err
			}
			err = dispatch(ctx, ds, ic, dOpt)
			if err != nil {
				return err
			}

			def, err = ds.state.Marshal(ctx, copts...)
			if err != nil {
				return err
			}

			res, err = opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
				Evaluate:     true,
				Definition:   def.ToPB(),
				CacheImports: opt.solver.Client().Config().CacheImports,
			})
			if res == nil {
				return parser.WithLocation(fmt.Errorf("failed to solve EXEC: %w", err), block.Location())
			}
			err = nil
		case *converter.CommandProcess:
			err, ok := handleProc(ctx, ds, cond, dOpt)
			if !ok {
				if err == nil {
					err = fmt.Errorf("unable to start [PROC]")
				}
				return parser.WithLocation(err, cond.Location())
			}

			if err != nil {
				errs = errors.Join(parser.WithLocation(err, cond.Location()), errs)
				continue forloop
			}

			if i == 0 {
				return exec(cmd.ConditionIF.Commands)
			} else {
				return exec(cmd.ConditionElse[i-1].Commands)
			}
		case *converter.CommandBuild:
			bs, err := dispatchBuild(ctx, *cond, opt)
			if err != nil {
				return err
			}

			def, err := bs.state.Marshal(ctx, llb.ProgressGroup(ifElseID, "IF/ELSE ==> " + cond.String(), true))
			if err != nil {
				return err
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
				return exec(cmd.ConditionIF.Commands)
			} else {
				return exec(cmd.ConditionElse[i-1].Commands)
			}
		default:
			return fmt.Errorf("unsupported conditional subcommand: %s", cond.Name())
		}

		pgName := cmd.String()
		if block, ok := block.(interface{ String() string }); ok {
			pgName = block.String()
		}
		def, err := ds.state.Marshal(ctx, llb.ProgressGroup(ifElseID, "IF/ELSE ==> " + pgName, true))
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
			return parser.WithLocation(errors.New("no conditional statement found"), block.Location())
		}

		ddef, err := d.state.Marshal(ctx, llb.ProgressGroup(ifElseID, "IF/ELSE ==> " + pgName, true))
		if err != nil {
			return err
		}

		res, err := opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
			Evaluate:     true,
			Definition:   ddef.ToPB(),
			CacheImports: opt.solver.Client().Config().CacheImports,
		})
		if err != nil {
			return parser.WithLocation(fmt.Errorf("failed to marshal state: %w", err), cmd.Location())
		}

		ctr, ctrErr = createContainer(ctx, dOpt.solver.Client(), execop, res.Ref)
		if ctrErr != nil {
			return parser.WithLocation(ctrErr, block.Location())
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
				return exec(cmd.ConditionIF.Commands)
			} else {
				return exec(cmd.ConditionElse[i-1].Commands)
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
		err, returnErr = startProcess(ctx, ctr, timeout, *execop, func() error {
			dClone.state = dClone.state.
				AddEnv("STDOUT", stdout.String()).
				AddEnv("STDERR", stderr.String())
			return exec(conditionalCommands)
		}, &nopCloser{stdout}, &nopCloser{stderr})
		if returnErr {
			return err
		}
		errs = errors.Join(errors.New(stderr.String()), parser.WithLocation(err, block.Location()), errs)
		continue forloop
	}

	if errs == nil || len(conds) == 1 { // NOTE: if no else condition => skip if condition error
		return nil
	}

	return fmt.Errorf("all conditions failed: %w", errs)
}
