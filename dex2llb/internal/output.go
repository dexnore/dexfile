package internal

import (
	"context"
	"fmt"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/flightcontrol"
)

var _ llb.Output = (*Output)(nil)

type Output struct {
	platform       string
	client         client.Client
	frontendOpt    map[string]string
	frontendInputs map[string]*pb.Definition
	cacheImports   []client.CacheOptionsEntry
	g              *flightcontrol.CachedGroup[llb.Output]
}

func NewOutput(c client.Client, opts map[string]string, inputs map[string]*pb.Definition, platform string, cache []client.CacheOptionsEntry) Output {
	return Output{
		platform:       platform,
		client:         c,
		frontendOpt:    opts,
		frontendInputs: inputs,
		cacheImports:   cache,
	}
}

func (o Output) ToInput(ctx context.Context, copts *llb.Constraints) (*pb.Input, error) {
	output, err := o.do(ctx)
	if err != nil {
		return nil, err
	}
	return output.ToInput(ctx, copts)
}

func (o Output) Vertex(ctx context.Context, copts *llb.Constraints) llb.Vertex {
	output, err := o.do(ctx)
	if err != nil {
		return &ErrorVertex{Err: err}
	}

	return output.Vertex(ctx, copts)
}

func (o Output) do(ctx context.Context) (llb.Output, error) {
	return o.g.Do(ctx, "initoutput", func(ctx context.Context) (llb.Output, error) {
		res, err := o.client.Solve(ctx, client.SolveRequest{
			Evaluate:       true,
			Frontend:       "dockerfile.v0",
			FrontendOpt:    o.frontendOpt,
			FrontendInputs: o.frontendInputs,
			CacheImports:   o.cacheImports,
		})
		if err != nil {
			return nil, err
		}

		ref, ok := res.FindRef(o.platform)
		if !ok {
			return nil, fmt.Errorf("no import found with platform %s", o.platform)
		}

		st, err := ref.ToState()
		if err != nil {
			return nil, err
		}

		imgKey := fmt.Sprintf("%s/%s", exptypes.ExporterImageConfigKey, o.platform)
		imgBytes := res.Metadata[imgKey]
		if len(imgBytes) == 0 {
			imgKey = exptypes.ExporterImageConfigKey
			imgBytes = res.Metadata[imgKey]
		}

		// var img *dockerspec.DockerOCIImage
		// if err := json.Unmarshal(imgBytes, img); err != nil {
		// 	i := emptyImage(tp)
		// 	img = &i
		// }
		// d.image = *img

		// var baseImg *dockerspec.DockerOCIImage
		baseImgKey := fmt.Sprintf("%s/%s", exptypes.ExporterImageBaseConfigKey, o.platform)
		baseImgBytes := res.Metadata[baseImgKey]
		if len(baseImgBytes) == 0 {
			baseImgKey = exptypes.ExporterImageBaseConfigKey
			baseImgBytes = res.Metadata[baseImgKey]
		}
		// if err := json.Unmarshal(baseImgBytes, baseImg); err != nil {
		// 	img = new(dockerspec.DockerOCIImage) // avoid nil pointer
		// 	*img = emptyImage(tp)
		// }
		// d.baseImg = baseImg

		return st.WithValue(imgKey, imgBytes).WithValue(baseImgKey, baseImgBytes).Output(), nil
	})
}
