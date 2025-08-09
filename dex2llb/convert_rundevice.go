//go:build dfrundevice

package dex2llb

import (
	instructions "github.com/dexnore/dexfile/converter"
	"github.com/moby/buildkit/client/llb"
)

func dispatchRunDevices(c *instructions.RunCommand) ([]llb.RunOption, error) {
	var out []llb.RunOption
	for _, device := range instructions.GetDevices(c) {
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
