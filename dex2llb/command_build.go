package dex2llb

import (
	"context"
	"fmt"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/identity"
)

func dispatchBuild(ctx context.Context, cmd converter.CommandBuild, opt dispatchOpt,  copts ...llb.ConstraintsOpt) (buildState *dispatchState, err error) {
	buildState, ok := opt.allDispatchStates.findImmutableStateByName(cmd.Stage)
	if !ok {
		return nil, parser.WithLocation(fmt.Errorf("no stage found with name %q", cmd.Stage), cmd.Location())
	}

	buildID := identity.NewID()
	localCopts := []llb.ConstraintsOpt{
		llb.WithCaps(*opt.llbCaps),
		llb.ProgressGroup(buildID, cmd.String(), false),
	}
	buildState.buildArgs = append(buildState.buildArgs, cmd.Args...)
	dOpt := opt.Clone()
	for _, cmd := range buildState.StageCommands() {
		ic, err := toCommand(cmd, dOpt.allDispatchStates)
		if err != nil {
			return nil, err
		}
		buildState.commands = append(buildState.commands, ic)
	}

	for _, cmd := range buildState.commands {
		if err := dispatch(ctx, buildState, cmd, dOpt, append(copts, localCopts...)...); err != nil {
			return nil, err
		}
	}

	buildState.state = buildState.state.WithOutput(buildState.state.Output())
	return buildState, nil
}
