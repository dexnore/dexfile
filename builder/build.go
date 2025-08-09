package builder

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/dexnore/dexfile/client"

	// "github.com/dexnore/dexfile/shiftleft"
	"github.com/dexnore/dexfile/solver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
)

func Build(ctx context.Context, c gwclient.Client) (_ *gwclient.Result, err error) {
	// if err := shiftleft.Error(c); err != nil {
	// 	return nil, err
	// }

	clnt, err := client.NewClient(c)
	if err != nil {
		return nil, err
	}

	if _, ok := clnt.BuildOpts().Opts["debug"]; ok {
		defer func() {
			if r := recover(); r != nil {
				err = errors.Join(err, fmt.Errorf("%+v", r))
			}
			if err != nil {
				err = errors.Join(err, fmt.Errorf("%s", debug.Stack()))
			}
		}()
	}

	slver, err := solver.New(clnt)
	if err != nil {
		return nil, err
	}

	return slver.Solve(ctx)
}
