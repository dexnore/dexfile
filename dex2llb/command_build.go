package dex2llb

import (
	"context"
	"fmt"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
)

func dispatchBuild(ctx context.Context, cmd converter.CommandBuild, opt dispatchOpt, copts ...llb.ConstraintsOpt) (buildState *dispatchState, err error) {
	dOpt, err := opt.Clone()
	if err != nil {
		return nil, err
	}
	dss := dOpt.allDispatchStates
	dss.states, dss.statesByName, err = dispatchStateCloneStates(dss.immutableStates, dss.immutableStatesByName)
	if err != nil {
		return nil, err
	}
	dss.Clean()
	buildState, ok := dss.findStateByName(cmd.Stage)
	if !ok {
		return nil, parser.WithLocation(fmt.Errorf("no stage found with name %q", cmd.Stage), cmd.Location())
	}

	for _, kvp := range cmd.Args {
		dOpt.buildArgValues[kvp.Key] = kvp.ValueString()
	}

	buildState.buildArgs = append(cmd.Args, buildState.buildArgs...)
	if err := fillDepsAndValidate(dss); err != nil {
		return nil, err
	}
	buildState, _, err = solveStage(ctx, buildState, opt.mutableBuildContextOutput, dOpt, copts...)
	return buildState, err
}
