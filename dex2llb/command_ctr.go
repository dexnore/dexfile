package dex2llb

import (
	"bytes"
	"context"
	"fmt"
	"strconv"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/dex2llb/internal"
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

func containerState(ctr *converter.CommandProcess, ds *dispatchStates) (llb.State, error) {
	return findState(ctr.From, ds)
}

func findState(state string, ds *dispatchStates) (st llb.State, err error) {
	index, err := strconv.Atoi(state)
	if err != nil {
		stn, ok := ds.findStateByName(state)
		if !ok {
			st = llb.Image(state)
		} else {
			st = stn.state
		}
	} else {
		stn, err := ds.findStateByIndex(index)
		if err != nil {
			return st, err
		}
		st = stn.state
	}
	return st, nil
}

func dispatchProc(ctx context.Context, d *dispatchState, cmd *converter.CommandProcess, proxy *llb.ProxyEnv, sources []*dispatchState, opt dispatchOpt, copts ...llb.ConstraintsOpt) (err error) {
	ds := d.Clone()
	dOpt, err := opt.Clone()
	if err != nil {
		return err
	}

	var (
		ifElseID                     = identity.NewID()
		localCopts                   = []llb.ConstraintsOpt{
			llb.WithCaps(*opt.llbCaps),
			llb.ProgressGroup(ifElseID, cmd.String(), false),
		}
		LocalCopts = append(copts, localCopts...)
		stdout = bytes.NewBuffer(nil)
		stderr = bytes.NewBuffer(nil)
	)

	dc, err := toCommand(cmd, opt.allDispatchStates)
	if err != nil {
		return err
	}
	if err = dispatchRun(ds, &cmd.RunCommand, proxy, sources, dOpt, LocalCopts...); err != nil {
		return err
	}

	def, err := ds.state.Marshal(ctx)
	if err != nil {
		return parser.WithLocation(err, cmd.Location())
	}

	execop, err := internal.MarshalToExecOp(def)
	if err != nil {
		return err
	}

	if execop == nil {
		return parser.WithLocation(errors.New("no conditional statement found"), cmd.Location())
	}

	ddef, err := d.state.Marshal(ctx)
	if err != nil {
		return err
	}

	res, err := opt.solver.Client().Solve(ctx, client.SolveRequest{
		Definition:   ddef.ToPB(),
		CacheImports: opt.solver.Client().Config().CacheImports,
	})
	if err != nil {
		return parser.WithLocation(fmt.Errorf("failed to marshal state: %w", err), cmd.Location())
	}

	ctrMounts, err := mountsForContainer(ctx, cmd, execop, dc.sources, res, ds, dOpt)
	if err != nil {
		return err
	}
	ctr, ctrErr := internal.CreateContainer(ctx, dOpt.solver.Client(), execop, ctrMounts)
	if ctrErr != nil {
		return parser.WithLocation(ctrErr, cmd.Location())
	}

	if execop.Exec != nil && execop.Exec.CdiDevices != nil {
		_, err := ds.opt.solver.Client().Solve(ctx, client.SolveRequest{
			Evaluate:     true,
			Definition:   def.ToPB(),
			CacheImports: dOpt.solver.Client().Config().CacheImports,
		})
		if err != nil {
			return parser.WithLocation(err, cmd.Location())
		}
		return nil
	}
	
	_, _, err = internal.StartProcess(ctx, ctr, cmd.TimeOut, *execop, func() (bool, error) {
		d.state = d.state.
			AddEnv("STDOUT", stripNewlineSuffix(stdout.String())[0]).
			AddEnv("STDERR", stripNewlineSuffix(stderr.String())[0])
		return false, nil
	}, internal.NopCloser(stdout), internal.NopCloser(stderr))
	return err
}

func mountsForContainer(ctx context.Context, ctr converter.WithExternalData, execop *internal.ExecOp, sources []*dispatchState, res *client.Result, d *dispatchState, opt dispatchOpt) (map[*pb.Mount]*client.Result, error) {
	var converterMounts = converter.GetMounts(ctr)
	var ctrMounts = make(map[*pb.Mount]*client.Result, len(converterMounts)+1)
	if ml := len(execop.Exec.Mounts); (ml != len(converterMounts)+1) || ml < 1 {
		return nil, errors.New("internal error: failed to create container")
	}
	ctrMounts[execop.Exec.Mounts[0]] = res
	for i := 1; i < len(execop.Exec.Mounts); i++ {
		mount := execop.Exec.Mounts[i]
		convMount := converterMounts[i-1]
		mountedState, err := dispatchExecOpMount(d, i-1, convMount, sources, opt)
		if err != nil {
			return nil, err
		}

		def, err := mountedState.Marshal(ctx, llb.WithCustomNamef("mounting %s to container", convMount.From))
		if err != nil {
			return nil, err
		}

		res, err := opt.solver.Client().Solve(ctx, client.SolveRequest{
			Definition:   def.ToPB(),
			CacheImports: opt.solver.Client().Config().CacheImports,
		})
		if err != nil {
			return nil, err
		}

		ctrMounts[mount] = res
	}
	return ctrMounts, nil
}
