package client

import (
	"maps"
	"slices"
	"strings"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/client/resolver"
	"github.com/moby/buildkit/frontend/gateway/client"
)

func NewClient(c client.Client) (*Client, error) {
	client := &Client{
		Client:      &resolver.WithResolveCache{Client: c},
		buildOpts:   BuildOpts{BuildOpts: c.BuildOpts()},
		ignoreCache: make([]string, 0),
	}

	if err := validateMinCaps(*client); err != nil {
		return nil, err
	}

	err := client.InitConfig()
	return client, err
}

func (c *Client) BuildOpts() client.BuildOpts {
	return c.buildOpts.BuildOpts
}

func (c *Client) IsNoCache(name string) bool {
	if len(c.ignoreCache) == 0 {
		return c.ignoreCache != nil
	}
	for _, n := range c.ignoreCache {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

func (c *Client) GetLocalSession(id string) (session string, found bool) {
	session, found = c.localSessionIDs[id]
	if !found {
		return c.buildOpts.SessionID, false
	}
	return
}

func (c *Client) InitConfig() (err error) {
	for _, parseAttr := range DefaultClientParseAttrs {
		configOpts := parseAttr(c.BuildOpts())
		if err := configOpts(&c.ClientConfig); err != nil {
			return err
		}
	}

	opts := c.BuildOpts().Opts
	c.ignoreCache = ParseIgnoreCache(opts)
	c.localSessionIDs = ParseLocalSessionIDs(opts)
	return nil
}

func (c *Client) Config() dexfile.ClientConfig {
	return c.ClientConfig
}

func (c *Client) Clone() dexfile.Client {
	client := &Client{
		buildOpts:       c.buildOpts.Clone(),
		ignoreCache:     slices.Clone(c.ignoreCache),
		localSessionIDs: maps.Clone(c.localSessionIDs),
		Client:          c,
		ClientConfig:    c.ClientConfig.Clone(),
	}
	return client
}
