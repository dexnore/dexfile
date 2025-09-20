package buildcontext

import (
	"context"
	"regexp"
	"strconv"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/context/internal"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	gwpb "github.com/moby/buildkit/frontend/gateway/pb"
	"github.com/moby/buildkit/util/gitutil"
	"github.com/pkg/errors"
)

func Context(ctx context.Context, c dexfile.Client, localOpts ...llb.LocalOption) (bc dexfile.BuildContext, err error) {
	defer func() {
		if err != nil {
			err = errors.Wrapf(err, "failed to create build context")
		}
	}()
	opts := c.BuildOpts().Opts
	localNameContext := contextKey(opts)
	bc = dexfile.BuildContext{
		ContextLocalName: dexfile.DefaultLocalNameContext,
		DexfileLocalName: dexfile.DefaultLocalNameDockerfile,
		Filename:         dexfile.DefaultDexfileName,
	}

	if v, ok := opts[KeyFilename]; ok {
		bc.Filename = v
	}

	if v, ok := opts[dexfile.DefaultLocalNameDockerfile]; ok {
		bc.DexfileLocalName = v
	}

	if v, ok := opts[KeyNameDockerfile]; ok {
		bc.ForceLocalDexfile = true
		bc.DexfileLocalName = v
	}

	if v, ok := opts[dexfile.DefaultLocalNameDexfile]; ok {
		bc.DexfileLocalName = v
	}

	if v, ok := opts[KeyNameDexfile]; ok {
		bc.ForceLocalDexfile = true
		bc.DexfileLocalName = v
	}

	switch SourceType(bc.DexfileLocalName, c.BuildOpts()) {
	case SourceGit:
		bc.Dexfile, _, err = internal.GitContext(bc.DexfileLocalName, keepGitDir(opts))
		if err != nil {
			return bc, err
		}
	case SourceHTTP:
		var filename string
		bc.Dexfile, filename, err = internal.HTTPContext(ctx, bc.DexfileLocalName, c)
		if err != nil {
			return bc, err
		}
		if filename != "" {
			bc.Filename = filename
		}
	case SourceInputs:
		bc.Dexfile, _, err = detectClientInputs(ctx, bc, c)
		if err != nil {
			return bc, err
		}
	}

	switch SourceType(opts[localNameContext], c.BuildOpts()) {
	case SourceGit:
		bc.Context, _, err = internal.GitContext(opts[localNameContext], keepGitDir(opts))
		if err != nil {
			return bc, err
		}
		if bc.Dexfile == nil {
			bc.Dexfile = bc.Context
		}
	case SourceHTTP:
		var filename string
		bc.Context, filename, err = internal.HTTPContext(ctx, opts[localNameContext], c)
		if err != nil {
			return bc, err
		}
		if filename != "" {
			bc.Filename = filename
		}
		if bc.Dexfile == nil {
			bc.Dexfile = bc.Context
		}
	case SourceInputs:
		var Dfile *llb.State
		Dfile, bc.Context, err = detectClientInputs(ctx, bc, c)
		if err != nil {
			return bc, err
		}
		if bc.Dexfile == nil {
			bc.Dexfile = Dfile
		}
	}

	if bc.Context != nil {
		if sub, ok := opts[KeyContextSubDir]; ok {
			bc.Context = scopeToSubDir(bc.Context, sub)
		}
	}

	if bc.Dexfile != nil {
		if sub, ok := opts[KeyDexfileSubDir]; ok {
			bc.Dexfile = scopeToSubDir(bc.Dexfile, sub)
		}
	}
	// Local Source

	return bc, nil
}

func contextKey(opts map[string]string) string {
	if contextKey, ok := opts[KeyNameContext]; ok {
		return contextKey
	}
	return dexfile.DefaultLocalNameContext
}

func keepGitDir(opts map[string]string) bool {
	keep, _ := strconv.ParseBool(opts[keyContextKeepGitDirArg])
	return keep
}

var httpPrefix = regexp.MustCompile(`^https?://`)

func SourceType(localNameContext string, opts gwclient.BuildOpts) sourceType {
	if _, err := gitutil.ParseGitRef(localNameContext); err == nil {
		return SourceGit
	}

	if httpPrefix.MatchString(localNameContext) {
		return SourceHTTP
	}

	if (&opts.Caps).Supports(gwpb.CapFrontendInputs) == nil {
		return SourceInputs
	}

	return SourceLocal
}

func detectClientInputs(ctx context.Context, bc dexfile.BuildContext, client dexfile.Client) (dex, context *llb.State, err error) {
	dex, context = bc.Dexfile, bc.Context
	inputs, err := client.Inputs(ctx)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to get frontend inputs")
	}

	if !bc.ForceLocalDexfile {
		if inputDexfile, ok := inputs[bc.DexfileLocalName]; ok {
			dex = &inputDexfile
		}
	}

	if inputCtx, ok := inputs[contextKey(client.BuildOpts().Opts)]; ok { // added support for 'contextKey'
		context = &inputCtx
	}

	return dex, context, nil
}

func scopeToSubDir(c *llb.State, dir string) *llb.State {
	bc := llb.Scratch().File(llb.Copy(*c, dir, "/", &llb.CopyInfo{
		CopyDirContentsOnly: true,
	}))
	return &bc
}
