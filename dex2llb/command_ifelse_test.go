package dex2llb_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/dexnore/dexfile"
	builder "github.com/dexnore/dexfile/dex2llb"
	dfclient "github.com/dexnore/dexfile/client"
	"github.com/tonistiigi/fsutil"

	dfc "github.com/dexnore/dexfile/context"
	"github.com/dexnore/dexfile/solver"
	"github.com/moby/buildkit/client"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/appcontext"
	"github.com/stretchr/testify/assert"
)

func TestIFELSE(t *testing.T) {
	df := `IF RUN echo "i am nil"
	ARG GO_VERSION=$STDOUT
ELSE
	ARG GO_VERSION=$STDERR
ENDIF
FROM busybox:latest
`


	bk, err := client.New(appcontext.Context(), "unix:///Users/sai/.lima/buildkit/sock/buildkitd.sock")
	assert.NoError(t, err)
	fsctx, err := fsutil.NewFS(filepath.Join(".."))
	assert.NoError(t, err)
	r, err := fsctx.Open("Dockerfile")
	assert.NoError(t, err)
	assert.NotNil(t, r)
	res, err := bk.Build(context.Background(), client.SolveOpt{
		Frontend: "gateway.v0",
		LocalMounts: map[string]fsutil.FS{
			"context": fsctx,
			"dockerfile": fsctx,
			"dexfile": fsctx,
		},
	}, "", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		cl, err := dfclient.NewClient(c)
		assert.NoError(t, err)
		slver, err := solver.New(cl)
		assert.NoError(t, err)
		// return slver.Solve(ctx)
		// assert.NoError(t, err)

		bc, err := dfc.New(cl)
		assert.NoError(t, err)
		st, _, _, _, err := builder.Dexfile2LLB(ctx, []byte(df), dexfile.ConvertOpt{
			Config: dexfile.ClientConfig{
				Frontend: "dexnore/dexfile:latest",
			},
			BC: bc,
			Client: cl,
			Solver: slver,
		})
		assert.NoError(t, err)
		assert.NotNil(t, st)
		envlist, err := st.Env(ctx)
		assert.Equal(t, "RUN echo \"i am nil\"", envlist)
		assert.Equal(t, "RUN echo \"i am nil\"", err)
		return gwclient.NewResult(), nil
	}, nil)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, nil, res)
}