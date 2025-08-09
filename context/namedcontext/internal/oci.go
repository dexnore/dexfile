package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dexnore/dexfile"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

func (nc *NamedContext) oci(ctx context.Context, inputRef string, client dexfile.Client, opt dexfile.ContextOpt) (*llb.State, *dockerspec.DockerOCIImage, error) {
	refSpec := strings.TrimPrefix(inputRef, "//")
	ref, err := reference.Parse(refSpec)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "could not parse oci-layout reference %q", refSpec)
	}
	named, ok := ref.(reference.Named)
	if !ok {
		return nil, nil, errors.Errorf("oci-layout reference %q has no name", ref.String())
	}
	dgstd, ok := named.(reference.Digested)
	if !ok {
		return nil, nil, errors.Errorf("oci-layout reference %q has no digest", named.String())
	}

	// for the dummy ref primarily used in log messages, we can use the
	// original name, since the store key may not be significant
	dummyRef, err := reference.ParseNormalizedNamed(nc.name)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "could not parse oci-layout reference %q", nc.name)
	}
	dummyRef, err = reference.WithDigest(dummyRef, dgstd.Digest())
	if err != nil {
		return nil, nil, errors.Wrapf(err, "could not wrap %q with digest", nc.name)
	}

	_, dgst, data, err := client.ResolveImageConfig(ctx, dummyRef.String(), sourceresolver.Opt{
		LogName:  fmt.Sprintf("[context %s] load metadata for %s", nc.nameWithPlatform, dummyRef.String()),
		Platform: opt.Platform,
		OCILayoutOpt: &sourceresolver.ResolveOCILayoutOpt{
			Store: sourceresolver.ResolveImageConfigOptStore{
				SessionID: client.BuildOpts().SessionID,
				StoreID:   named.Name(),
			},
		},
	})
	if err != nil {
		return nil, nil, err
	}

	var img dockerspec.DockerOCIImage
	if err := json.Unmarshal(data, &img); err != nil {
		return nil, nil, errors.Wrap(err, "could not parse oci-layout image config")
	}

	ociOpt := []llb.OCILayoutOption{
		llb.WithCustomName("[context " + nc.nameWithPlatform + "] OCI load from client"),
		llb.OCIStore(client.BuildOpts().SessionID, named.Name()),
	}
	if opt.Platform != nil {
		ociOpt = append(ociOpt, llb.Platform(*opt.Platform))
	}
	st := llb.OCILayout(
		dummyRef.String(),
		ociOpt...,
	)
	st, err = st.WithImageConfig(data)
	if err != nil {
		return nil, nil, err
	}
	if opt.CaptureDigest != nil {
		*opt.CaptureDigest = dgst
	}
	return &st, &img, nil
}
