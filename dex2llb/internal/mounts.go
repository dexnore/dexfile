package internal

import (
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
)

func ConvertProtoToMounts(converter.Mount) (map[*pb.Mount]*client.Result, error) {
	return nil, nil
}