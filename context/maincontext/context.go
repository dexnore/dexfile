package maincontext

import (
	"context"

	"github.com/dexnore/dexfile"
	dexcontext "github.com/dexnore/dexfile/context/dexfile"
	"github.com/dexnore/dexfile/context/internal"
	"github.com/moby/buildkit/client/llb"
	"github.com/pkg/errors"
)

func DefaultMainContext(opts ...llb.LocalOption) *llb.State {
	opts = append([]llb.LocalOption{
		llb.SharedKeyHint(dexfile.DefaultLocalNameContext),
		internal.WithInternalName("load build context"),
	}, opts...)
	st := llb.Local(dexfile.DefaultLocalNameContext, opts...)
	return &st
}

func MainContext(ctx context.Context, c dexfile.Client, bc dexfile.BuildContext, opts ...llb.LocalOption) (*llb.State, error) {
	if bc.Context != nil {
		return bc.Context, nil
	}

	dcontext := dexcontext.New(c, bc)
	src, err := dcontext.Dexfile(ctx, dexfile.DefaultDexfileName)
	if err != nil {
		return nil, err
	}

	excludes, err := src.DexnorePatterns(ctx, c, bc)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read dexnore patterns")
	}

	sessionID, _ := c.GetLocalSession(bc.ContextLocalName)
	opts = append([]llb.LocalOption{
		llb.SessionID(sessionID),
		llb.ExcludePatterns(excludes),
		llb.SharedKeyHint(bc.ContextLocalName),
		internal.WithInternalName("load build context"),
	}, opts...)

	st := llb.Local(bc.ContextLocalName, opts...)

	return &st, nil
}
