package internal

import (
	"bytes"
	"context"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/localoutput"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/patternmatcher/ignorefile"
	"github.com/pkg/errors"
)

func (nc *NamedContext) local(ctx context.Context, inputRef string, client dexfile.Client, opt dexfile.ContextOpt) (*llb.State, *dockerspec.DockerOCIImage, error) {
	sessionID, _ := client.GetLocalSession(inputRef)
	st := llb.Local(inputRef,
		llb.SessionID(sessionID),
		llb.FollowPaths([]string{dexfile.DefaultDexnoreName}),
		llb.SharedKeyHint("context:"+nc.nameWithPlatform+"-"+dexfile.DefaultDexnoreName),
		llb.WithCustomName("[context "+nc.nameWithPlatform+"] load "+dexfile.DefaultDexnoreName),
		llb.Differ(llb.DiffNone, false),
	)
	def, err := st.Marshal(ctx)
	if err != nil {
		return nil, nil, err
	}
	res, err := client.Solve(ctx, gwclient.SolveRequest{
		Evaluate:   true,
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, nil, err
	}
	ref, err := res.SingleRef()
	if err != nil {
		return nil, nil, err
	}
	var excludes []string
	if !opt.NoDexnore {
		dt, _ := ref.ReadFile(ctx, gwclient.ReadRequest{
			Filename: dexfile.DefaultDexnoreName,
		}) // error ignored

		if len(dt) != 0 {
			excludes, err = ignorefile.ReadAll(bytes.NewBuffer(dt))
			if err != nil {
				return nil, nil, errors.Wrapf(err, "failed parsing %s", dexfile.DefaultDexnoreName)
			}
		}
	}

	localOutput := localoutput.Async(
		inputRef,
		nc.nameWithPlatform,
		sessionID,
		excludes,
		opt.AsyncLocalOpts,
	)
	st = llb.NewState(localOutput)
	return &st, nil, nil
}
