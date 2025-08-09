package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dexnore/dexfile"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

func externalFrontend(ctx context.Context, c dexfile.Client, data []byte) (ref string, loc []parser.Range, ok bool) {
	if v, ok := c.BuildOpts().Opts["cmdline"]; ok {
		return v, nil, false
	}

	if cmdline, ok := c.BuildOpts().Opts[KeySyntaxArg]; ok {
		p := strings.SplitN(strings.TrimSpace(cmdline), " ", 2)
		return isExternalFrontend(ctx, c, xFE{ref: p[0], loc: nil})
	}

	if ref, _, loc, ok := parser.DetectSyntax(data); ok {
		return isExternalFrontend(ctx, c, xFE{ref: ref, loc: loc})
	}

	return "", nil, false
}

type xFE struct { // external frontend options
	ref string
	loc []parser.Range
}

func isExternalFrontend(ctx context.Context, c dexfile.Client, opts xFE) (string, []parser.Range, bool) {
	ref, err := reference.ParseAnyReference(opts.ref)
	if err != nil {
		return "", nil, false
	}
	_, _, image, err := c.ResolveImageConfig(ctx, ref.String(), sourceresolver.Opt{
		LogName: fmt.Sprintf("detecting %s: is external frontend?", opts.ref),
		ImageOpt: &sourceresolver.ResolveImageOpt{
			ResolveMode: c.Config().ImageResolveMode.String(),
		},
	})

	var mfest ocispecs.Descriptor
	json.Unmarshal(image, &mfest)
	if mfest.Annotations[dexnoreRevisionKey] != dexfile.Version && err == nil {
		return opts.ref, opts.loc, true
	}

	return "", nil, false
}
