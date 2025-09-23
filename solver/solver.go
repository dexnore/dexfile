package solver

import (
	"context"

	"github.com/dexnore/dexfile"
	buildClient "github.com/dexnore/dexfile/context"
	"github.com/dexnore/dexfile/context/buildcontext"
	"github.com/dexnore/dexfile/dex2llb"
	"github.com/dexnore/dexfile/gateway"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/frontend/subrequests/lint"
	"github.com/moby/buildkit/frontend/subrequests/outline"
	"github.com/moby/buildkit/frontend/subrequests/targets"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/apicaps"
	"github.com/pkg/errors"
)

func New(client dexfile.Client) (solver *Solver, err error) {
	solver = &Solver{
		client: client,
	}

	solver.bClient, err = buildClient.New(client)
	return solver, err
}

type Solver struct {
	client  dexfile.Client
	bClient dexfile.BuildClient
}

func (s *Solver) Solve(ctx context.Context) (res *gwclient.Result, err error) {
	var src dexfile.Source
	src, err = s.bClient.Dexfile(ctx)
	if err != nil {
		return nil, err
	}

	convertOpt := dexfile.ConvertOpt{
		Config:       s.client.Config(),
		Client:       s.client,
		BC:           s.bClient,
		SourceMap:    src.Sources(),
		MetaResolver: s.client,
		Solver:       s,
		LLBCaps:      new(apicaps.CapSet),
		Warn: func(rulename, description, url, msg string, location []parser.Range) {
			startLine := 0
			if len(location) > 0 {
				startLine = location[0].Start.Line
			}
			msg = linter.LintFormatShort(rulename, msg, startLine)
			src.WarnSources(ctx, msg, warnOpts(location, [][]byte{[]byte(description)}, url))
		},
	}

	*convertOpt.LLBCaps = s.client.LLBCaps()

	bc, err := s.bClient.BuildContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create build context")
	}
	gway := gateway.New(s.client, bc)
	dexfile2llb, err := dex2llb.New()
	if err != nil {
		return nil, err
	}
	var ok bool
	res, ok, err = gway.HandleRequest(ctx, src, gateway.RequestHandler{
		ExternalFrontend: func(ctx context.Context, ref string) (*gwclient.Result, error) {
			return ForwardGateway(ctx, s.client, ref)
		},
		Outline: func(ctx context.Context) (*outline.Outline, error) {
			return dexfile2llb.Outline(ctx, src.Sources().Data, convertOpt)
		},
		ListTargets: func(ctx context.Context) (*targets.List, error) {
			return dexfile2llb.ListTargets(ctx, src.Sources().Data)
		},
		Lint: func(ctx context.Context) (*lint.LintResults, error) {
			return dexfile2llb.Lint(ctx, src.Sources().Data, convertOpt)
		},
		Dexfile: func(ctx context.Context) (*gwclient.Result, error) {
			return Build(ctx, s.client, src, dexfile2llb, convertOpt)
		},
	})

	if ok {
		return res, nil
	}

	return res, err
}

func (s *Solver) Client() dexfile.Client {
	return s.client
}

func (s *Solver) With(client dexfile.Client, bc dexfile.BuildContext) (dexfile.Solver, error) {
	if client == nil {
		c := s.client.Clone()
		c.DelOpt("cmdline", "source", "build-arg:BUILDKIT_SYNTAX")
		c.SetOpt(buildcontext.KeyFilename, bc.Filename)
		// c.SetOpt(config.KeyTarget, d.imports.Target)
		return New(c)
	}

	return New(client)
}

func warnOpts(r []parser.Range, detail [][]byte, url string) gwclient.WarnOpts {
	opts := gwclient.WarnOpts{Level: 1, Detail: detail, URL: url}
	if r == nil {
		return opts
	}
	opts.Range = []*pb.Range{}
	for _, r := range r {
		opts.Range = append(opts.Range, &pb.Range{
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
	return opts
}
