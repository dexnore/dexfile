package solver

import (
	"context"

	"github.com/moby/buildkit/frontend/gateway/client"
	gwpb "github.com/moby/buildkit/frontend/gateway/pb"
	"github.com/moby/buildkit/solver/pb"
	"github.com/pkg/errors"
)

func ForwardGateway(ctx context.Context, c client.Client, ref string) (*client.Result, error) {
	opts := c.BuildOpts().Opts
	if opts == nil {
		opts = map[string]string{}
	}
	opts["source"] = ref
	opts["cmdline"] = ref // added

	gwcaps := c.BuildOpts().Caps
	var frontendInputs map[string]*pb.Definition
	if (&gwcaps).Supports(gwpb.CapFrontendInputs) == nil {
		inputs, err := c.Inputs(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get frontend inputs")
		}

		frontendInputs = make(map[string]*pb.Definition)
		for name, state := range inputs {
			def, err := state.Marshal(ctx)
			if err != nil {
				return nil, err
			}
			frontendInputs[name] = def.ToPB()
		}
	}

	return c.Solve(ctx, client.SolveRequest{
		Frontend:       "gateway.v0",
		FrontendOpt:    opts,
		FrontendInputs: frontendInputs,
	})
}
