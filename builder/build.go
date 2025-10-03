package builder

import (
	"context"
	"runtime/debug"

	"github.com/dexnore/dexfile/client"
	"github.com/dexnore/dexfile/solver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/pkg/errors"
)

func Build(ctx context.Context, c gwclient.Client) (_ *gwclient.Result, err error) {
	clnt, err := client.NewClient(c)
	if err != nil {
		return nil, err
	}

	if _, ok := clnt.BuildOpts().Opts["debug"]; ok {
		defer func() {
			if r := recover(); r != nil {
				err = errors.Wrapf(err, "%+v", r)
			}
			if err != nil {
				err = errors.Wrapf(err, "%s", debug.Stack())
			}
		}()
	}

	slver, err := solver.New(clnt)
	if err != nil {
		return nil, err
	}

	return slver.Solve(ctx)
}
