package dex2llb

import (
	"github.com/pkg/errors"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
)

func dispatchRunNetwork(c converter.WithExternalData) (llb.RunOption, error) {
	network := converter.GetNetwork(c)

	switch network {
	case converter.NetworkDefault:
		return nil, nil
	case converter.NetworkNone:
		return llb.Network(pb.NetMode_NONE), nil
	case converter.NetworkHost:
		return llb.Network(pb.NetMode_HOST), nil
	default:
		return nil, errors.Errorf("unsupported network mode %q", network)
	}
}
