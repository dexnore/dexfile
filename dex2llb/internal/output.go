package internal

import (
	"context"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
	"github.com/pkg/errors"
)

var _ llb.Output = &SimpleOutput{}
type SimpleOutput struct {
	Output llb.Output
	Err error
}

func NewSimpleOutput(output llb.Output, err error) *SimpleOutput {
	return &SimpleOutput{
		Output: output,
		Err: err,
	}
}

func (o SimpleOutput) ToInput(ctx context.Context, copts *llb.Constraints) (*pb.Input, error) {
	if o.Err != nil {
		return nil, o.Err
	}

	if o.Output == nil {
		return nil, errors.Errorf("output is nil")
	}

	return o.Output.ToInput(ctx, copts)
}

func (o SimpleOutput) Vertex(ctx context.Context, copts *llb.Constraints) (v llb.Vertex) {
	if o.Err != nil {
		return &ErrorVertex{Err: o.Err}
	}
	if o.Output == nil {
		return &ErrorVertex{Err: errors.Errorf("Vertex output is nil")}
	}
	return o.Output.Vertex(ctx, copts)
}