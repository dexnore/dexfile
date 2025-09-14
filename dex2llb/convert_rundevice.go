//go:build dfrundevice

package dex2llb

import (
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/client/llb"
)

func dispatchRunDevices(c converter.WithExternalData) ([]llb.RunOption, error) {
	var out []llb.RunOption
	for _, device := range converter.GetDevices(c) {
		deviceOpts := []llb.CDIDeviceOption{
			llb.CDIDeviceName(device.Name),
		}
		if !device.Required {
			deviceOpts = append(deviceOpts, llb.CDIDeviceOptional)
		}
		out = append(out, llb.AddCDIDevice(deviceOpts...))
	}
	return out, nil
}
