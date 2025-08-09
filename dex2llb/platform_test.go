package dex2llb

import (
	"testing"

	"github.com/containerd/platforms"
	"github.com/dexnore/dexfile"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestResolveBuildPlatforms(t *testing.T) {
	dummyPlatform1 := ocispecs.Platform{Architecture: "DummyArchitecture1", OS: "DummyOS1"}
	dummyPlatform2 := ocispecs.Platform{Architecture: "DummyArchitecture2", OS: "DummyOS2"}

	// BuildPlatforms is set and TargetPlatform is set
	opt := dexfile.ConvertOpt{TargetPlatform: &dummyPlatform1}
	opt.Config.BuildPlatforms = []ocispecs.Platform{dummyPlatform2}
	result := buildPlatformOpt(&opt).buildPlatforms
	assert.Equal(t, []ocispecs.Platform{dummyPlatform2}, result)

	// BuildPlatforms is not set and TargetPlatform is set
	opt = dexfile.ConvertOpt{TargetPlatform: &dummyPlatform1}
	result = buildPlatformOpt(&opt).buildPlatforms
	assert.Equal(t, []ocispecs.Platform{dummyPlatform1}, result)

	// BuildPlatforms is set and TargetPlatform is not set
	opt = dexfile.ConvertOpt{TargetPlatform: nil}
	opt.Config.BuildPlatforms = []ocispecs.Platform{dummyPlatform2}
	result = buildPlatformOpt(&opt).buildPlatforms
	assert.Equal(t, []ocispecs.Platform{dummyPlatform2}, result)

	// BuildPlatforms is not set and TargetPlatform is not set
	opt = dexfile.ConvertOpt{}
	result = buildPlatformOpt(&opt).buildPlatforms
	assert.Equal(t, []ocispecs.Platform{platforms.DefaultSpec()}, result)
}

func TestResolveTargetPlatform(t *testing.T) {
	dummyPlatform := ocispecs.Platform{Architecture: "DummyArchitecture", OS: "DummyOS"}

	// TargetPlatform is set
	opt := dexfile.ConvertOpt{TargetPlatform: &dummyPlatform}
	result := buildPlatformOpt(&opt)
	assert.Equal(t, dummyPlatform, result.targetPlatform)

	// TargetPlatform is not set
	opt = dexfile.ConvertOpt{TargetPlatform: nil}
	result = buildPlatformOpt(&opt)
	assert.Equal(t, result.buildPlatforms[0], result.targetPlatform)
}

func TestImplicitTargetPlatform(t *testing.T) {
	dummyPlatform := ocispecs.Platform{Architecture: "DummyArchitecture", OS: "DummyOS"}

	// TargetPlatform is set
	opt := dexfile.ConvertOpt{TargetPlatform: &dummyPlatform}
	result := buildPlatformOpt(&opt).implicitTarget
	assert.Equal(t, false, result)

	// TargetPlatform is not set
	opt = dexfile.ConvertOpt{TargetPlatform: nil}
	result = buildPlatformOpt(&opt).implicitTarget
	assert.Equal(t, true, result)
}
