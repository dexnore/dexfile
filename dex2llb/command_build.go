package dex2llb

import (
	"fmt"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
)

func dispatchBuild(cmd converter.CommandBuild, opt dispatchOpt) (buildState *dispatchState, err error) {
	buildState, ok := opt.allDispatchStates.findStateByName(cmd.Stage)
	if !ok {
		return nil, parser.WithLocation(fmt.Errorf("no stage found with name %q", cmd.Stage), cmd.Location())
	}

	buildState.buildArgs = append(buildState.buildArgs, cmd.Args...)
	return buildState, nil
}
