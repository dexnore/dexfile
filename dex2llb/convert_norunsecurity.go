//go:build !dfrunsecurity

package dex2llb

import (
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/client/llb"
)

func dispatchRunSecurity(_ converter.WithExternalData) (llb.RunOption, error) {
	return nil, nil
}
