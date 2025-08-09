//go:build !dfrunsecurity

package dex2llb

import (
	instructions "github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/client/llb"
)

func dispatchRunSecurity(_ *instructions.RunCommand) (llb.RunOption, error) {
	return nil, nil
}
