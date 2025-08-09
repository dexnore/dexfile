package source

import (
	"context"
	"sync"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
)

type Source struct {
	dexnoreMu   sync.Mutex
	Dexnore     []byte
	DexnoreName string
	*llb.SourceMap
	Warn func(context.Context, string, client.WarnOpts)
}
