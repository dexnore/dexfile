package context

import (
	"context"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/context/buildcontext"
	dexfilectx "github.com/dexnore/dexfile/context/dexfile"
	"github.com/dexnore/dexfile/context/maincontext"
	nc "github.com/dexnore/dexfile/context/namedcontext"
	"github.com/moby/buildkit/client/llb"
	"github.com/pkg/errors"
)

func New(client dexfile.Client) (*Client, error) {
	return &Client{
		client: client,
	}, nil
}

func (c *Client) BuildContext(ctx context.Context, opts ...llb.LocalOption) (dexfile.BuildContext, error) {
	return c.g.Do(ctx, "initcontext", func(ctx context.Context) (dexfile.BuildContext, error) {
		bc, err := buildcontext.Context(ctx, c.client, opts...)
		if err != nil {
			err = errors.Wrap(err, "failed to create build client")
		}

		return bc, err
	})
}

func (c *Client) Dexnore(ctx context.Context, opts ...llb.LocalOption) ([]string, error) {
	src, err := c.Dexfile(ctx, opts...)
	if err != nil {
		return nil, err
	}

	bc, err := c.BuildContext(ctx, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create build context")
	}

	if bc.Context != nil {
		return nil, nil
	}

	return src.DexnorePatterns(ctx, c.client, bc)
}

func (c *Client) Dexfile(ctx context.Context, opts ...llb.LocalOption) (dexfile.Source, error) {
	bc, err := c.BuildContext(ctx, opts...)
	if err != nil {
		return nil, err
	}

	dex := dexfilectx.New(c.client, bc)
	return dex.Dexfile(ctx, "Dexfile", opts...)
}

func (c *Client) MainContext(ctx context.Context, opts ...llb.LocalOption) (*llb.State, error) {
	bc, err := c.BuildContext(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return maincontext.MainContext(ctx, c.client, bc, opts...)
}

func (c *Client) NamedContext(name string, opts dexfile.ContextOpt) (dexfile.NamedContext, error) {
	return nc.NamedContext(name, c.client, opts)
}

func (c *Client) BaseContext(name string, opts dexfile.ContextOpt) (dexfile.NamedContext, error) {
	return nc.BaseContext(name, c.client, opts)
}
