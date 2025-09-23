package internal

import (
	"context"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
)

var _ llb.Vertex = (*ErrorVertex)(nil)

type ErrorVertex struct {
	Err error
}

func (v *ErrorVertex) Validate(ctx context.Context, copts *llb.Constraints) error {
	return v.Err
}

func (v *ErrorVertex) Marshal(context.Context, *llb.Constraints) (digest.Digest, []byte, *pb.OpMetadata, []*llb.SourceLocation, error) {
	return "", nil, nil, nil, v.Err
}

func (v *ErrorVertex) Output() llb.Output {
	return nil
}

func (v *ErrorVertex) Inputs() []llb.Output {
	return nil
}
