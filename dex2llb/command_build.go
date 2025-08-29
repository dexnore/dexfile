package dex2llb

import (
	"context"
	"fmt"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
)

func dispatchBuild(ctx context.Context, cmd converter.CommandBuild, opt dispatchOpt,  copts ...llb.ConstraintsOpt) (buildState *dispatchState, err error) {
	buildState, ok := opt.allDispatchStates.findImmutableStateByName(cmd.Stage)
	if !ok {
		return nil, parser.WithLocation(fmt.Errorf("no stage found with name %q", cmd.Stage), cmd.Location())
	}
	buildState.opt = opt

	// buildID := identity.NewID()
	// localCopts := []llb.ConstraintsOpt{
	// 	llb.WithCaps(*opt.llbCaps),
	// 	llb.ProgressGroup(buildID, cmd.String(), false),
	// }

	for _, cmd := range buildState.StageCommands() {
		ic, err := toCommand(cmd, opt.allDispatchStates)
		if err != nil {
			return nil, err
		}
		buildState.commands = append(buildState.commands, ic)
	}
	buildState.buildArgs = append(buildState.buildArgs, cmd.Args...)
	buildState, err = solveStage(ctx, buildState, opt.mutableBuildContextOutput, opt)
	return nil, fmt.Errorf("%+v\n\n\n\n\n%+v\n%w", buildState, buildState.state, err)
}
