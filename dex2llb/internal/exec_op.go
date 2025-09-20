package internal

import (
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
)

type ExecOp struct {
	Exec        *pb.ExecOp
	Inputs      []*pb.Input
	Platform    *pb.Platform
	Constraints *pb.WorkerConstraints
}

func SolveOp(baseOp *pb.Op) *ExecOp {
	switch op := baseOp.Op.(type) {
	case *pb.Op_Exec:
		return &ExecOp{
			Exec:        op.Exec,
			Inputs:      baseOp.Inputs,
			Platform:    baseOp.Platform,
			Constraints: baseOp.Constraints,
		}
	}
	return nil
}

func MarshalToExecOp(def *llb.Definition) (*ExecOp, error) {
	var execop *ExecOp
	for i := len(def.Def) - 1; i >= 0; i-- {
		def := def.Def[i]
		var pop pb.Op
		if err := pop.UnmarshalVT(def); err != nil {
			return nil, err
		}
		if execop = SolveOp(&pop); execop != nil {
			break
		}
	}
	return execop, nil
}
