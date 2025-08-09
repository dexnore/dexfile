package source

import (
	"bytes"
	"context"

	"github.com/dexnore/dexfile"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/patternmatcher/ignorefile"
	"github.com/pkg/errors"
)

func (s *Source) DexnorePatterns(ctx context.Context, c dexfile.Client, config dexfile.BuildContext) ([]string, error) {
	s.dexnoreMu.Lock()
	defer s.dexnoreMu.Unlock()
	if s.Dexnore == nil {
		sessionID, _ := c.GetLocalSession(config.ContextLocalName)
		st := llb.Local(config.ContextLocalName,
			llb.SessionID(sessionID),
			llb.FollowPaths([]string{dexfile.DefaultDexnoreName}),
			llb.SharedKeyHint(config.ContextLocalName+"-"+dexfile.DefaultDexnoreName),
			WithInternalName("load "+dexfile.DefaultDexnoreName),
			llb.Differ(llb.DiffNone, false),
		)
		def, err := st.Marshal(ctx, MarshalOpts(c.BuildOpts())...)
		if err != nil {
			return nil, err
		}
		res, err := c.Solve(ctx, client.SolveRequest{
			Definition: def.ToPB(),
		})
		if err != nil {
			return nil, err
		}
		ref, err := res.SingleRef()
		if err != nil {
			return nil, err
		}
		dt, _ := ref.ReadFile(ctx, client.ReadRequest{ // ignore error
			Filename: dexfile.DefaultDexnoreName,
		})
		if dt == nil {
			dt = []byte{}
		}
		s.Dexnore = dt
		s.DexnoreName = dexfile.DefaultDexnoreName
	}
	var err error
	var excludes []string
	if len(s.Dexnore) != 0 {
		excludes, err = ignorefile.ReadAll(bytes.NewBuffer(s.Dexnore))
		if err != nil {
			return nil, errors.Wrapf(err, "failed parsing %s", s.DexnoreName)
		}
	}
	return excludes, nil
}

func (s *Source) Sources() *llb.SourceMap {
	return s.SourceMap
}

func (s *Source) WarnSources(ctx context.Context, msg string, opts client.WarnOpts) {
	s.Warn(ctx, msg, opts)
}

func MarshalOpts(c client.BuildOpts) []llb.ConstraintsOpt {
	return []llb.ConstraintsOpt{llb.WithCaps(c.Caps)}
}

func WithInternalName(name string) llb.ConstraintsOpt {
	return llb.WithCustomName("[internal] " + name)
}
