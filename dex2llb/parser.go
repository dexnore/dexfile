package dex2llb

import (
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/pkg/errors"
)

func parseAndValidateDexfile(ast *parser.Node, lint *linter.Linter) (stages []converter.Adder, metaCmds []converter.Command, err error) {
	stages, metaCmds, err = converter.Parse(ast, lint)
	if err != nil {
		return stages, metaCmds, err
	}
	if len(stages) == 0 {
		return stages, metaCmds, errors.New("dexfile contains no stages to build")
	}

	validateStageNames(stages, lint)
	validateCommandCasing(stages, lint)

	return stages, metaCmds, nil
}
