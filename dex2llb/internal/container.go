package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
)

func convertMounts(mounts map[*pb.Mount]*client.Result) (cm []client.Mount) {
	for m, r := range mounts {
		mnt := client.Mount{
			Dest:      m.Dest,
			ResultID:  m.ResultID,
			Selector:  m.Selector,
			Ref:       r.Ref,
			Readonly:  m.Readonly,
			MountType: m.MountType,
			CacheOpt:  m.CacheOpt,
			SecretOpt: m.SecretOpt,
			SSHOpt:    m.SSHOpt,
		}
		cm = append(cm, mnt)
	}
	return cm
}

func CreateContainer(ctx context.Context, c client.Client, execop *ExecOp, mounts map[*pb.Mount]*client.Result) (client.Container, error) {
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

	ctrReq := client.NewContainerRequest{
		Mounts:      convertMounts(mounts),
		Hostname:    execop.Exec.Meta.GetHostname(),
		NetMode:     execop.Exec.GetNetwork(),
		ExtraHosts:  slices.Clone(execop.Exec.Meta.GetExtraHosts()),
		Platform:    &platform,
		Constraints: &constraints,
	}

	return c.NewContainer(ctx, ctrReq)
}

func startProcess(ctx context.Context, ctr client.Container, execop *pb.ExecOp, stdout, stderr io.WriteCloser) (_ client.ContainerProcess, err error) {
	if execop == nil {
		return nil, fmt.Errorf("failed to create ctr process %+v", execop)
	}
	startReq := client.StartRequest{
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

func StartProcess(ctx context.Context, ctr client.Container, timeout *time.Duration, execop ExecOp, handleCond func() (bool, error), stdout, stderr io.WriteCloser) (retErr, buildCmd bool, err error) {
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
	pidCtx, cancel := context.WithTimeoutCause(ctx, dur, fmt.Errorf("timeout: conditional instruction exceeded %s. Increase the --timeout if necessary", FormatDuration(dur)))
	defer cancel()
	var pid client.ContainerProcess
	pid, err = startProcess(pidCtx, ctr, execop.Exec, stdout, stderr)
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
