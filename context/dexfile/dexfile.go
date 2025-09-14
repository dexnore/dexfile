package dexfile

import (
	"context"
	"path"
	"strings"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/context/internal"
	"github.com/dexnore/dexfile/source"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/pkg/errors"
)

func (d *df) Dexfile(ctx context.Context, lang string, opts ...llb.LocalOption) (dexfile.Source, error) {
	var src *llb.State
	if !d.bc.ForceLocalDexfile {
		if d.bc.Dexfile != nil {
			src = d.bc.Dexfile
		}
	}

	if src == nil {
		src = detectLocalDexfile(d.bc, d.client, opts...)
	}
	d.bc.Dexfile = src

	def, err := d.bc.Dexfile.Marshal(ctx, internal.MarshalOpts(d.client.BuildOpts())...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal local source")
	}

	defVtx, err := def.Head()
	if err != nil {
		return nil, err
	}

	res, err := d.client.Solve(ctx, client.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to resolve dexfile")
	}

	ref, err := res.SingleRef()
	if err != nil {
		return nil, err
	}

	dt, err := ref.ReadFile(ctx, client.ReadRequest{
		Filename: d.bc.Filename,
	})
	if err != nil {
		if path.Base(d.bc.Filename) == dexfile.DefaultDexfileName {
			var err1 error
			dt, err1 = ref.ReadFile(ctx, client.ReadRequest{
				Filename: path.Join(path.Dir(d.bc.Filename), strings.ToLower(dexfile.DefaultDexfileName)),
			})
			if err1 == nil {
				err = nil
			}
		}
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read %q", "dexfile")
		}
	}
	smap := llb.NewSourceMap(d.bc.Dexfile, d.bc.Filename, lang, dt)
	smap.Definition = def

	dt, err = ref.ReadFile(ctx, client.ReadRequest{
		Filename: d.bc.Filename + dexfile.DefaultDexnoreName,
	})

	sourcemap := &source.Source{
		SourceMap: smap,
		Warn: func(ctx context.Context, msg string, opts client.WarnOpts) {
			if opts.Level == 0 {
				opts.Level = 1
			}
			if opts.SourceInfo == nil {
				opts.SourceInfo = &pb.SourceInfo{
					Data:       smap.Data,
					Filename:   smap.Filename,
					Language:   smap.Language,
					Definition: smap.Definition.ToPB(),
				}
			}
			d.client.Warn(ctx, defVtx, msg, opts)
		},
	}

	if err == nil {
		sourcemap.Dexnore = dt
		sourcemap.DexnoreName = d.bc.Filename + dexfile.DefaultDexnoreName
	}

	return sourcemap, nil
}

func detectLocalDexfile(bc dexfile.BuildContext, client dexfile.Client, opts ...llb.LocalOption) *llb.State {
	name := "load build definition from " + bc.Filename
	filenames := []string{bc.Filename, bc.Filename + ".dexnore"}

	// dockerfile is also supported casing moby/moby#10858
	if path.Base(bc.Filename) == dexfile.DefaultDexfileName {
		filenames = append(filenames, path.Join(path.Dir(bc.Filename), strings.ToLower(dexfile.DefaultDexfileName)))
	}

	sessionID, _ := client.GetLocalSession(bc.DexfileLocalName)
	opts = append([]llb.LocalOption{
		llb.FollowPaths(filenames),
		llb.SessionID(sessionID),
		llb.SharedKeyHint(bc.DexfileLocalName),
		internal.WithInternalName(name),
		llb.Differ(llb.DiffNone, false),
	}, opts...)

	lsrc := llb.Local(bc.DexfileLocalName, opts...)
	return &lsrc
}
