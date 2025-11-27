package dex2llb

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/dexnore/dexfile/dex2llb/internal"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/identity"
)

type WriteCloseStringer interface {
	io.WriteCloser
	String() string
}

func handleIfElse(ctx context.Context, d *dispatchState, cmd converter.ConditionIfElse, exec func([]converter.Command, ...llb.ConstraintsOpt) (bool, error), opt dispatchOpt, copts ...llb.ConstraintsOpt) (breakCmd bool, err error) {
	if cmd.ConditionIF == nil || cmd.ConditionIF.Condition == nil {
		return false, errors.New("'if' condition cannot be nil")
	}

	conds := []converter.Command{cmd.ConditionIF.Condition}
	for _, elseCond := range cmd.ConditionElse {
		conds = append(conds, elseCond.Condition)
	}

	var ctr gwclient.Container
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
	)

	var (
		prevStdout = bytes.NewBuffer(nil)
		prevStderr = bytes.NewBuffer(nil)
	)

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

		blockCmd, err := toCommand(block, dOpt.allDispatchStates)
		if err != nil {
			return false, err
		}
		ds.commands = append(ds.commands, blockCmd)

		timeout := 10 * time.Second
		if i == 0 && cmd.ConditionIF.TimeOut != nil {
			timeout = *cmd.ConditionIF.TimeOut
		} else if i > 0 && cmd.ConditionElse[i-1].TimeOut != nil {
			timeout = *cmd.ConditionElse[i-1].TimeOut
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if _, err := dispatch(ctx, ds, blockCmd, dOpt, localCopts...); err != nil {
			prevStderr.WriteString(err.Error())
			continue
		}

		def, err := ds.state.Marshal(ctx)
		if err != nil {
			return false, err
		}

		_, err = opt.solver.Client().Solve(ctx, gwclient.SolveRequest{
			Evaluate:     true,
			Definition:   def.ToPB(),
			CacheImports: opt.solver.Client().Config().CacheImports,
		})
		if err != nil {
			prevStderr.WriteString(err.Error())
			continue
		}

		d.state = d.state.
			AddEnv("STDOUT", stripNewlineSuffix(internal.Stdout(ds.state))[0]).
			AddEnv("STDERR", stripNewlineSuffix(internal.Stderr(ds.state))[0])
		if i == 0 {
			return exec(cmd.ConditionIF.Commands, localCopts...)
		} else {
			return exec(cmd.ConditionElse[i-1].Commands, localCopts...)
		}
	}

	return false, nil
}

func stripNewlineSuffix(s string) []string {
	if strings.HasSuffix(s, "\n") {
		return strings.Split(s, "\n")
	}
	return []string{s}
}
