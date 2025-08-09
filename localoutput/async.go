package localoutput

import (
	"context"
	"sync"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
)

func Async(name string, nameWithPlatform string, sessionID string, excludes []string, extraOpts func() []llb.LocalOption) *asyncLocalOutput {
	return &asyncLocalOutput{
		name:             name,
		nameWithPlatform: nameWithPlatform,
		sessionID:        sessionID,
		excludes:         excludes,
		extraOpts:        extraOpts,
	}
}

// asyncLocalOutput is an llb.Output that computes an llb.Local
// on-demand instead of at the time of initialization.
type asyncLocalOutput struct {
	llb.Output
	name             string
	nameWithPlatform string
	sessionID        string
	excludes         []string
	extraOpts        func() []llb.LocalOption
	once             sync.Once
}

func (a *asyncLocalOutput) ToInput(ctx context.Context, constraints *llb.Constraints) (*pb.Input, error) {
	a.once.Do(a.do)
	return a.Output.ToInput(ctx, constraints)
}

func (a *asyncLocalOutput) Vertex(ctx context.Context, constraints *llb.Constraints) llb.Vertex {
	a.once.Do(a.do)
	return a.Output.Vertex(ctx, constraints)
}

func (a *asyncLocalOutput) do() {
	var extraOpts []llb.LocalOption
	if a.extraOpts != nil {
		extraOpts = a.extraOpts()
	}
	opts := append([]llb.LocalOption{
		llb.WithCustomName("[context " + a.nameWithPlatform + "] load from client"),
		llb.SessionID(a.sessionID),
		llb.SharedKeyHint("context:" + a.nameWithPlatform),
		llb.ExcludePatterns(a.excludes),
	}, extraOpts...)

	st := llb.Local(a.name, opts...)
	a.Output = st.Output()
}
