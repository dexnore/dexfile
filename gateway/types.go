package gateway

import (
	"context"

	"github.com/dexnore/dexfile"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	lint "github.com/moby/buildkit/frontend/subrequests/lint"
	outline "github.com/moby/buildkit/frontend/subrequests/outline"
	targets "github.com/moby/buildkit/frontend/subrequests/targets"
)

type Gateway interface {
	HandleRequest(context.Context, RequestHandler) (*gwclient.Result, bool, error)
}

type RequestHandler struct {
	ExternalFrontend func(ctx context.Context, ref string) (*gwclient.Result, error)
	Outline          func(ctx context.Context) (*outline.Outline, error)
	ListTargets      func(ctx context.Context) (*targets.List, error)
	Lint             func(ctx context.Context) (*lint.LintResults, error)
	Dexfile          func(ctx context.Context) (*gwclient.Result, error)
}

type gateway struct {
	client  dexfile.Client
	context dexfile.BuildContext
}
