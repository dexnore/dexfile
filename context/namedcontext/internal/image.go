package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dexnore/dexfile"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/util/imageutil"
	"github.com/pkg/errors"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
)

func (nc *NamedContext) image(ctx context.Context, inputRef string, count int, client dexfile.Client, opt dexfile.ContextOpt) (*llb.State, *dockerspec.DockerOCIImage, error) {
	ref := strings.TrimPrefix(inputRef, "//")
	if ref == dexfile.EmptyImageName {
		st := llb.Scratch()
		return &st, nil, nil
	}

	imgOpt := []llb.ImageOption{
		llb.WithCustomName("[context " + nc.nameWithPlatform + "] " + ref),
	}
	if opt.Platform != nil {
		imgOpt = append(imgOpt, llb.Platform(*opt.Platform))
	}

	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return nil, nil, err
	}

	named = reference.TagNameOnly(named)

	ref, dgst, data, err := client.ResolveImageConfig(ctx, named.String(), sourceresolver.Opt{
		LogName:  fmt.Sprintf("[context %s] load metadata for %s", nc.nameWithPlatform, ref),
		Platform: opt.Platform,
		ImageOpt: &sourceresolver.ResolveImageOpt{
			ResolveMode: opt.ResolveMode,
		},
	})
	if err != nil {
		e := &imageutil.ResolveToNonImageError{}
		if errors.As(err, &e) {
			before, after, ok := strings.Cut(e.Updated, "://")
			if !ok {
				return nil, nil, errors.Errorf("could not parse ref: %s", e.Updated)
			}

			client.SetOpt(contextPrefix+nc.nameWithPlatform, before+":"+after)

			ncnew, err := Named(nc.name, nc.nameWithPlatform, client, nc.opt)
			if err != nil {
				return nil, nil, err
			}
			if ncnew == nil {
				return nil, nil, nil
			}
			return ncnew.load(ctx, count+1)
		}
		return nil, nil, err
	}

	var img dockerspec.DockerOCIImage
	if err := json.Unmarshal(data, &img); err != nil {
		return nil, nil, err
	}
	img.Created = nil

	st := llb.Image(ref, imgOpt...)
	st, err = st.WithImageConfig(data)
	if err != nil {
		return nil, nil, err
	}
	if opt.CaptureDigest != nil {
		*opt.CaptureDigest = dgst
	}
	return &st, &img, nil
}
