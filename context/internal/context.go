package internal

import (
	"context"
	"path/filepath"
	"regexp"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/gitutil"
	"github.com/pkg/errors"
)

func GitContext(ref string, keepGit bool) (*llb.State, string, error) {
	g, err := gitutil.ParseGitRef(ref)
	if err != nil {
		return nil, "", err
	}
	commit := g.Commit
	if g.SubDir != "" {
		commit += ":" + g.SubDir
	}
	gitOpts := []llb.GitOption{WithInternalName("load git source " + ref)}
	if keepGit {
		gitOpts = append(gitOpts, llb.KeepGitDir())
	}

	st := llb.Git(g.Remote, commit, gitOpts...)
	return &st, g.SubDir, nil
}

var httpPrefix = regexp.MustCompile(`^https?://`)

func HTTPContext(ctx context.Context, ref string, c client.Client) (*llb.State, string, error) {
	filename := "context"
	if httpPrefix.MatchString(ref) {
		st := llb.HTTP(ref, llb.Filename(filename), WithInternalName("load remote build context"))
		return detectHTTPContext(ctx, &st, filename, c)
	}
	return nil, "", nil
}

func detectHTTPContext(ctx context.Context, st *llb.State, filename string, c client.Client) (*llb.State, string, error) {
	def, err := st.Marshal(ctx, MarshalOpts(c.BuildOpts())...)
	if err != nil {
		return nil, filename, errors.Wrapf(err, "failed to marshal httpcontext")
	}
	res, err := c.Solve(ctx, client.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, filename, errors.Wrapf(err, "failed to resolve httpcontext")
	}

	ref, err := res.SingleRef()
	if err != nil {
		return nil, filename, err
	}

	dt, err := ref.ReadFile(ctx, client.ReadRequest{
		Filename: filename,
		Range: &client.FileRange{
			Length: 1024,
		},
	})
	if err != nil {
		return nil, filename, errors.Wrapf(err, "failed to read downloaded context")
	}
	if isArchive(dt) {
		bc := llb.Scratch().File(llb.Copy(*st, filepath.Join("/", filename), "/", &llb.CopyInfo{
			AttemptUnpack: true,
		}))
		return &bc, "", nil
	}
	return st, filename, nil
}

func MarshalOpts(c client.BuildOpts) []llb.ConstraintsOpt {
	return []llb.ConstraintsOpt{llb.WithCaps(c.Caps)}
}

func WithInternalName(name string) llb.ConstraintsOpt {
	return llb.WithCustomName("[internal] " + name)
}
