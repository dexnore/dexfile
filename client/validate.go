package client

import (
	"github.com/moby/buildkit/solver/pb"
	"github.com/pkg/errors"
)

func validateMinCaps(c Client) error {
	caps := c.BuildOpts().LLBCaps

	if err := caps.Supports(pb.CapFileBase); err != nil {
		return errors.Wrap(err, "needs BuildKit 0.5 or later")
	}

	return nil
}
