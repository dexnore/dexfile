package dexfile

import (
	"maps"
	"slices"
	"time"

	"github.com/moby/buildkit/client/llb"
)

func WithInternalName(name string) llb.ConstraintsOpt {
	return llb.WithCustomName("[internal] " + name)
}

func (c ClientConfig) Clone() ClientConfig {
	var epoch time.Time
	if c.Epoch != nil {
		epoch = *c.Epoch
	}
	ret := c

	ret.Epoch = &epoch
	ret.Labels = maps.Clone(c.Labels)
	ret.TargetPlatforms = slices.Clone(c.TargetPlatforms)

	return ret
}
