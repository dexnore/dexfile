//go:build dfrunsecurity

package dex2llb

import (
	"github.com/pkg/errors"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
)

func dispatchRunSecurity(c converter.WithExternalData) (llb.RunOption, error) {
	security := converter.GetSecurity(c)

	switch security {
	case converter.SecurityInsecure:
		return llb.Security(pb.SecurityMode_INSECURE), nil
	case converter.SecuritySandbox:
		return llb.Security(pb.SecurityMode_SANDBOX), nil
	default:
		return nil, errors.Errorf("unsupported security mode %q", security)
	}
}
