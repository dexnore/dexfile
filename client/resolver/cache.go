// source: https://github.com/moby/buildkit/blob/10a81797a96c5a0d23d35c3561e897cd8d69fc3d/frontend/dockerfile/builder/resolvecache.go
package resolver

import (
	"context"
	"fmt"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/flightcontrol"
	digest "github.com/opencontainers/go-digest"
)

// withResolveCache wraps client.Client so that ResolveImageConfig
// calls are cached and deduplicated via flightcontrol.CachedGroup
type WithResolveCache struct {
	client.Client
	g flightcontrol.CachedGroup[*resolveResult]
}

type resolveResult struct {
	ref  string
	dgst digest.Digest
	cfg  []byte
}

var _ client.Client = &WithResolveCache{}

func (c *WithResolveCache) ResolveImageConfig(ctx context.Context, ref string, opt sourceresolver.Opt) (string, digest.Digest, []byte, error) {
	c.g.CacheError = true
	optHash, err := hashstructure.Hash(opt, hashstructure.FormatV2, nil)
	if err != nil {
		return "", "", nil, err
	}
	key := fmt.Sprintf("%s,%d", ref, optHash)
	res, err := c.g.Do(ctx, key, func(ctx context.Context) (*resolveResult, error) {
		ref, dgst, cfg, err := c.Client.ResolveImageConfig(ctx, ref, opt)
		if err != nil {
			return nil, err
		}
		return &resolveResult{ref, dgst, cfg}, nil
	})
	if err != nil {
		return "", "", nil, err
	}
	return res.ref, res.dgst, res.cfg, nil
}
