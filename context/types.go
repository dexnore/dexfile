package context

import (
	"github.com/dexnore/dexfile"
	"github.com/moby/buildkit/util/flightcontrol"
)

type Client struct {
	g      flightcontrol.CachedGroup[dexfile.BuildContext]
	client dexfile.Client
}
