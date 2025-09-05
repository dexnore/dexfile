package solver

import (
	"context"
	"sync"

	"github.com/containerd/platforms"
	"github.com/dexnore/dexfile"

	"github.com/dexnore/dexfile/instructions/parser"
	bresult "github.com/dexnore/dexfile/result"
	"github.com/dexnore/dexfile/sbom"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/errdefs"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/solver/result"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

func Build(ctx context.Context, c dexfile.Client, src dexfile.Source, dex2llb dexfile.Dexfile2LLB, convertOpt dexfile.ConvertOpt) (res *gwclient.Result, err error) {
	defer func() {
		var el *parser.LocationError
		if errors.As(err, &el) {
			for _, l := range el.Locations {
				err = wrapSource(err, src.Sources(), l)
			}
		}
	}()

	opts := c.BuildOpts().Opts
	var scanner sbom.Scanner
	if c.Config().SBOM != nil {
		// TODO: scanner should pass policy
		scanner, err = sbom.CreateSBOMScanner(ctx, c, c.Config().SBOM.Generator, sourceresolver.Opt{
			LogName: "dexfile: sbom scanner",
			ImageOpt: &sourceresolver.ResolveImageOpt{
				ResolveMode: opts["image-resolve-mode"],
			},
		}, c.Config().SBOM.Parameters)
		if err != nil {
			return nil, err
		}
	}

	scanTargets := sync.Map{}

	rb, err := bresult.Build(ctx, func(ctx context.Context, platform *ocispecs.Platform, idx int) (gwclient.Reference, *dockerspec.DockerOCIImage, *dockerspec.DockerOCIImage, error) {
		opt := convertOpt
		opt.TargetPlatform = platform
		if idx != 0 {
			opt.Warn = nil
		}

		st, img, baseImg, scanTarget, err := dex2llb.Compile(ctx, src.Sources().Data, opt)
		if err != nil {
			return nil, nil, nil, err
		}

		def, err := st.Marshal(ctx)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to marshal LLB definition")
		}

		r, err := c.Solve(ctx, gwclient.SolveRequest{
			Definition:   def.ToPB(),
			CacheImports: c.Config().CacheImports,
		})
		if err != nil {
			return nil, nil, nil, err
		}

		ref, err := r.SingleRef()
		if err != nil {
			return nil, nil, nil, err
		}

		var p ocispecs.Platform
		if platform != nil {
			p = *platform
		} else {
			p = platforms.DefaultSpec()
		}
		scanTargets.Store(platforms.FormatAll(platforms.Normalize(p)), scanTarget)

		return ref, &img, baseImg, nil
	}, c.Config())
	if err != nil {
		return nil, err
	}

	if scanner != nil {
		if err := rb.EachPlatform(ctx, func(ctx context.Context, id string, p ocispecs.Platform) error {
			v, ok := scanTargets.Load(id)
			if !ok {
				return errors.Errorf("no scan targets for %s", id)
			}
			target, ok := v.(*sbom.SBOMTargets)
			if !ok {
				return errors.Errorf("invalid scan targets for %T", v)
			}

			var opts []llb.ConstraintsOpt
			if target.IgnoreCache {
				opts = append(opts, llb.IgnoreCache)
			}
			att, err := scanner(ctx, id, target.Core, target.Extras, opts...)
			if err != nil {
				return err
			}

			attSolve, err := result.ConvertAttestation(&att, func(st *llb.State) (gwclient.Reference, error) {
				def, err := st.Marshal(ctx)
				if err != nil {
					return nil, err
				}
				r, err := c.Solve(ctx, gwclient.SolveRequest{
					Definition: def.ToPB(),
				})
				if err != nil {
					return nil, err
				}
				return r.Ref, nil
			})
			if err != nil {
				return err
			}
			rb.AddAttestation(id, *attSolve)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	return rb.Finalize()
}

func wrapSource(err error, sm *llb.SourceMap, ranges []parser.Range) error {
	if sm == nil {
		return err
	}
	s := &errdefs.Source{
		Info: &pb.SourceInfo{
			Data:       sm.Data,
			Filename:   sm.Filename,
			Language:   sm.Language,
			Definition: sm.Definition.ToPB(),
		},
		Ranges: make([]*pb.Range, 0, len(ranges)),
	}
	for _, r := range ranges {
		s.Ranges = append(s.Ranges, &pb.Range{
			Start: &pb.Position{
				Line:      int32(r.Start.Line),
				Character: int32(r.Start.Character),
			},
			End: &pb.Position{
				Line:      int32(r.End.Line),
				Character: int32(r.End.Character),
			},
		})
	}
	return errdefs.WithSource(err, s)
}
