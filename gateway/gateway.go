package gateway

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/dexnore/dexfile"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/frontend/subrequests"
	lint "github.com/moby/buildkit/frontend/subrequests/lint"
	outline "github.com/moby/buildkit/frontend/subrequests/outline"
	targets "github.com/moby/buildkit/frontend/subrequests/targets"
	"github.com/moby/buildkit/solver/errdefs"
	"github.com/moby/buildkit/solver/pb"
	"github.com/pkg/errors"
)

func New(client dexfile.Client, bc dexfile.BuildContext) *gateway {
	return &gateway{
		client:  client,
		context: bc,
	}
}

func (g *gateway) HandleRequest(ctx context.Context, src dexfile.Source, handler RequestHandler) (res *gwclient.Result, ok bool, err error) {
	opts := g.client.BuildOpts().Opts
	allowForward, capsError := validateCaps(opts["frontend.caps"])
	if !allowForward && capsError != nil {
		return nil, false, capsError
	}

	if ref, loc, ok := externalFrontend(ctx, g.client, src.Sources().Data); ok && handler.ExternalFrontend != nil {
		res, err := handler.ExternalFrontend(ctx, ref)
		if err != nil && len(errdefs.Sources(err)) == 0 {
			if loc == nil {
				return nil, false, errors.Wrapf(err, "failed with %s = %s", KeySyntaxArg, ref)
			}

			return nil, false, wrapSource(err, src.Sources(), loc)
		}

		return res, true, nil
	}

	if capsError != nil {
		return nil, false, capsError
	}

	if req, ok := g.client.BuildOpts().Opts[keyRequestID]; ok {
		switch req {
		case subrequests.RequestSubrequestsDescribe:
			res, err := describe(handler)
			return res, true, err
		case outline.SubrequestsOutlineDefinition.Name:
			if f := handler.Outline; f != nil {
				o, err := f(ctx)
				if err != nil {
					return nil, false, err
				}
				if o == nil {
					return nil, true, nil
				}
				res, err := o.ToResult()
				return res, true, err
			}
		case targets.SubrequestsTargetsDefinition.Name:
			if f := handler.ListTargets; f != nil {
				targets, err := f(ctx)
				if err != nil {
					return nil, false, err
				}
				if targets == nil {
					return nil, true, nil
				}
				res, err := targets.ToResult()
				return res, true, err
			}
		case lint.SubrequestLintDefinition.Name:
			if f := handler.Lint; f != nil {
				warnings, err := f(ctx)
				if err != nil {
					return nil, false, err
				}
				if warnings == nil {
					return nil, true, nil
				}
				res, err := warnings.ToResult(nil)
				return res, true, err
			}
		default:
			return nil, false, errors.Errorf("unknown request %q", req)
		}
	}

	res, err = handler.Dexfile(ctx)
	return res, false, err
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

func describe(h RequestHandler) (*gwclient.Result, error) {
	all := []subrequests.Request{}
	if h.Outline != nil {
		all = append(all, outline.SubrequestsOutlineDefinition)
	}
	if h.ListTargets != nil {
		all = append(all, targets.SubrequestsTargetsDefinition)
	}
	all = append(all, subrequests.SubrequestsDescribeDefinition)
	dt, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return nil, err
	}

	b := bytes.NewBuffer(nil)
	if err := subrequests.PrintDescribe(dt, b); err != nil {
		return nil, err
	}

	res := gwclient.NewResult()
	res.Metadata = map[string][]byte{
		"result.json": dt,
		"result.txt":  b.Bytes(),
		"version":     []byte(subrequests.SubrequestsDescribeDefinition.Version),
	}
	return res, nil
}
