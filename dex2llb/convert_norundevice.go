//go:build !dfrundevice

package dex2llb

import (
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/client/llb"
	"github.com/pkg/errors"
)

func dispatchRunDevices(c converter.WithExternalData) ([]llb.RunOption, error) {
	if len(converter.GetDevices(c)) > 0 {
		return nil, errors.Errorf("device feature is only supported in Dockerfile frontend 1.14.0-labs or later")
	}
	return nil, nil
}
