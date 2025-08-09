package dex2llb

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
)

func dispatchFunction(ctx context.Context, d *dispatchState, cmd converter.Function, opt dispatchOpt) (err error) {
	defer func () {
		if err != nil {
			err = parser.WithLocation(err, cmd.Location())
		}
	}()
	if cmd.Action != nil {
		if strings.EqualFold(*cmd.Action, "call") {
			return handleFunctionCall(ctx, cmd, d, opt)
		}

		return fmt.Errorf("unsupported function action: %q", *cmd.Action)
	}
	return handleFunctionDefination(cmd, opt)
}

func handleFunctionCall(ctx context.Context, cmd converter.Function, d *dispatchState, opt dispatchOpt) error {
	var (
		function converter.Function
		ok bool
	)
	if function, ok = opt.functions[cmd.FuncName]; !ok {
		return fmt.Errorf("unknown function: %q", cmd.FuncName)
	}

	buildArgs := slices.Clone(d.buildArgs)
	d.buildArgs = append(d.buildArgs, append(function.Args, cmd.Args...)...)

	for _, cmd := range function.Commands {
		cmd, err := toCommand(cmd, opt.allDispatchStates)
		if err != nil {
			return err
		}
		if err := dispatch(ctx, d, cmd, opt); err != nil {
			return err
		}
	}

	d.buildArgs = buildArgs
	return nil
}

func handleFunctionDefination(cmd converter.Function, opt dispatchOpt) error {
	opt.functions[cmd.FuncName] = cmd
	return nil
}
