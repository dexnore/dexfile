package internal

import (
	"context"
	"encoding/json"

	"github.com/dexnore/dexfile"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

func (nc *NamedContext) inputs(ctx context.Context, inputRef string, client dexfile.Client) (*llb.State, *dockerspec.DockerOCIImage, error) {
	inputs, err := client.Inputs(ctx)
	if err != nil {
		return nil, nil, err
	}
	st, ok := inputs[inputRef]
	if !ok {
		return nil, nil, errors.Errorf("invalid input %s for %s", inputRef, nc.nameWithPlatform)
	}
	md, ok := client.BuildOpts().Opts[inputMetadataPrefix+inputRef]
	if ok {
		m := make(map[string][]byte)
		if err := json.Unmarshal([]byte(md), &m); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to parse input metadata %s", md)
		}
		var img *dockerspec.DockerOCIImage
		if dtic, ok := m[exptypes.ExporterImageConfigKey]; ok {
			st, err = st.WithImageConfig(dtic)
			if err != nil {
				return nil, nil, err
			}
			if err := json.Unmarshal(dtic, &img); err != nil {
				return nil, nil, errors.Wrapf(err, "failed to parse image config for %s", nc.nameWithPlatform)
			}
		}
		return &st, img, nil
	}
	return &st, nil, nil
}
