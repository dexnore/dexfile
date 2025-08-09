package client

import (
	"github.com/dexnore/dexfile"
	"github.com/moby/buildkit/frontend/gateway/client"
)

type Client struct {
	client.Client
	dexfile.ClientConfig
	buildOpts       BuildOpts
	ignoreCache     []string
	localSessionIDs map[string]string
}

type BuildOpts struct {
	client.BuildOpts
}
