package dex2llb

import (
	"context"

	"github.com/containerd/platforms"
	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/sbom"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/subrequests/lint"
	"github.com/moby/buildkit/frontend/subrequests/outline"
	"github.com/moby/buildkit/frontend/subrequests/targets"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

type Dex2LLB struct{}

func New() (*Dex2LLB, error) {
	return &Dex2LLB{}, nil
}

func (*Dex2LLB) ListTargets(ctx context.Context, dt []byte) (*targets.List, error) {
	return ListTargets(ctx, dt)
}

func (*Dex2LLB) Lint(ctx context.Context, dt []byte, opt dexfile.ConvertOpt) (*lint.LintResults, error) {
	return DexfileLint(ctx, dt, opt)
}

func (*Dex2LLB) Outline(ctx context.Context, dt []byte, opt dexfile.ConvertOpt) (*outline.Outline, error) {
	return Dexfile2Outline(ctx, dt, opt)
}

func (*Dex2LLB) Compile(ctx context.Context, dt []byte, opt dexfile.ConvertOpt) (llb.State, dockerspec.DockerOCIImage, *dockerspec.DockerOCIImage, *sbom.SBOMTargets, error) {
	st, img, baseImg, sbom, err := Dexfile2LLB(ctx, dt, opt)
	if st == nil {
		st = new(llb.State)
		*st = llb.Scratch()
	}

	if img == nil {
		img = &dockerspec.DockerOCIImage{
			Image: v1.Image{
				Platform: platforms.DefaultSpec(),
			},
		}
	}
	return *st, *img, baseImg, sbom, err
}
