package internal

import (
	"context"
	"fmt"
	"strings"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/context/internal"
	"github.com/moby/buildkit/client/llb"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

type NamedContext struct {
	input            string
	name             string
	nameWithPlatform string
	client           dexfile.Client
	opt              dexfile.ContextOpt
}

func (nc *NamedContext) Load(ctx context.Context) (*llb.State, *dockerspec.DockerOCIImage, error) {
	return nc.load(ctx, 0)
}

func (nc *NamedContext) load(ctx context.Context, count int) (*llb.State, *dockerspec.DockerOCIImage, error) {
	opt := nc.opt
	if count > maxContextRecursion {
		return nil, nil, errors.New("context recursion limit exceeded; this may indicate a cycle in the provided source policies: " + nc.input)
	}

	vv := strings.SplitN(nc.input, ":", 2)
	if len(vv) != 2 {
		return nil, nil, errors.Errorf("invalid context specifier %s for %s", nc.input, nc.nameWithPlatform)
	}

	// allow git@ without protocol for SSH URLs for backwards compatibility
	if strings.HasPrefix(vv[0], "git@") {
		vv[0] = "git"
	}

	switch vv[0] {
	case "docker-image":
		return nc.image(ctx, vv[1], count+1, nc.client, opt)
	case "git":
		st, _, err := internal.GitContext(nc.input, true)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid git context %s: %w", nc.input, err)
		}
		return st, nil, nil
	case "http", "https":
		st, _, err := internal.GitContext(nc.input, true)
		if err != nil {
			httpst := llb.HTTP(nc.input, llb.WithCustomName("[context "+nc.nameWithPlatform+"] "+nc.input))
			st = &httpst
		}
		return st, nil, nil
	case "oci-layout":
		return nc.oci(ctx, vv[1], nc.client, opt)
	case "local":
		return nc.local(ctx, vv[1], nc.client, opt)
	case "input":
		return nc.inputs(ctx, vv[1], nc.client)
	default:
		return nil, nil, errors.Errorf("unsupported context source %s for %s", vv[0], nc.nameWithPlatform)
	}
}
