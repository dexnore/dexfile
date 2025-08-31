package dex2llb

import (
	"context"
	"fmt"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
)

func dispatchBuild(ctx context.Context, cmd converter.CommandBuild, opt dispatchOpt,  copts ...llb.ConstraintsOpt) (buildState *dispatchState, err error) {
	dOpt := opt.Clone()
	dss := dOpt.allDispatchStates
	dss.states, dss.statesByName = dispatchStateCloneStates(dss.immutableStates, dss.immutableStatesByName)
	// dss.Clean()
	buildState, ok := dss.findStateByName(cmd.Stage)
	if !ok {
		return nil, parser.WithLocation(fmt.Errorf("no stage found with name %q", cmd.Stage), cmd.Location())
	}
	
	buildState.buildArgs = append(cmd.Args, buildState.buildArgs...)
	if err := fillDepsAndValidate(dss); err != nil {
		return nil, err
	}
	buildState, _, err = solveStage(ctx, buildState, opt.mutableBuildContextOutput, dOpt)
	return buildState, err
}

// return nil, fmt.Errorf(
// 	`base: %+v

// 	state: %+v

// 	resolved: %+v
// 	dispatched: %+v
// 	unregistered: %+v
// 	err: %w


// 	commands: %+v


// 	deps: %+v
// 	`, 
// 	buildState.base,
// 	buildState.state,
// 	buildState.resolved,
// 	buildState.dispatched,
// 	buildState.unregistered,
// 	err,
// 	buildState.commands,
// 	buildState.deps,
// )
