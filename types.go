package dexfile

import (
	"context"
	"time"

	"github.com/dexnore/dexfile/sbom"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/frontend/subrequests/lint"
	"github.com/moby/buildkit/frontend/subrequests/outline"
	"github.com/moby/buildkit/frontend/subrequests/targets"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/apicaps"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

type ClientConfig struct {
	BuildArgs        map[string]string // build arguments
	Frontend         string            // frontend name
	CgroupParent     string            // cgroup parent for the build
	Epoch            *time.Time        // epoch for the build
	ExtraHosts       []llb.HostIP
	CacheIDNamespace string
	ImageResolveMode llb.ResolveMode
	Hostname         string            // hostname for the build
	Target           string            // target for the build
	Labels           map[string]string // labels for the build
	NetworkMode      pb.NetMode
	ShmSize          int64
	Ulimits          []*pb.Ulimit
	Devices          []*pb.CDIDevice
	LinterConfig     *linter.Config

	CacheImports           []client.CacheOptionsEntry // cache imports for the build
	TargetPlatforms        []ocispecs.Platform        // target platforms for the build
	BuildPlatforms         []ocispecs.Platform
	MultiPlatformRequested bool
	SBOM                   *sbom.SBOM
}

type ClientConfigOpt func(*ClientConfig) error
type ClientParseAttr func(client.BuildOpts) ClientConfigOpt

type Client interface {
	client.Client
	BuildOpts
	IsNoCache(string) bool
	GetLocalSession(string) (string, bool)
	Config() ClientConfig
	InitConfig() error
	Clone() Client
}

type BuildOpts interface {
	// WorkersInfo
	SetOpt(key, value string) error
	DelOpt(key string) error
	WithSession(string)
	// AsProduct(string)
	Caps() apicaps.CapSet
	LLBCaps() apicaps.CapSet
}

type WorkersInfo interface {
	AddOrReplaceWorker(WorkerInfo) bool
	Worker(string) (WorkerInfo, bool)
	ListWorkers() []WorkerInfo
	RemoveWorker(string) (WorkerInfo, error)
}

type WorkerInfo interface {
	ID() string
	Label(string) (string, bool)
	SupportsPlatform(ocispecs.Platform) bool
	Equal(WorkerInfo) bool
}

type BuildContext struct {
	Context           *llb.State // set if not local
	Dexfile           *llb.State // override remoteContext if set
	ContextLocalName  string
	DexfileLocalName  string
	Filename          string
	ForceLocalDexfile bool
}

type ContextOpt struct {
	NoDexnore      bool
	AsyncLocalOpts func() []llb.LocalOption
	Platform       *ocispecs.Platform
	ResolveMode    string
	CaptureDigest  *digest.Digest
}

type BuildClient interface {
	Dexnore(ctx context.Context, opts ...llb.LocalOption) ([]string, error)
	Dexfile(ctx context.Context, opts ...llb.LocalOption) (Source, error)
	MainContext(ctx context.Context, opts ...llb.LocalOption) (*llb.State, error)
	NamedContext(name string, opt ContextOpt) (NamedContext, error)
	BaseContext(name string, opts ContextOpt) (NamedContext, error)
	BuildContext(ctx context.Context, opts ...llb.LocalOption) (BuildContext, error)
}

type Source interface {
	DexnorePatterns(ctx context.Context, client Client, config BuildContext) ([]string, error)
	Location(r []*pb.Range) llb.ConstraintsOpt
	WarnSources(context.Context, string, client.WarnOpts)
	Sources() *llb.SourceMap
}

type NamedContext interface {
	Load(ctx context.Context) (*llb.State, *dockerspec.DockerOCIImage, error)
}

type BFlags interface {
	AddBool(name string, def bool) Flag
	AddString(name string, def string) Flag
	AddStrings(name string) Flag
	Parse() error
	Used() []string

	// dexfile specific
	Args() []string
	Error() error
}

type Flag interface {
	IsUsed() bool
	IsTrue() bool

	// Dexfile specific
	Name() string
	Value() string
	StringValues() []string
}

type ConvertOpt struct {
	Config         ClientConfig
	BC             BuildClient
	Client         Client
	Solver         Solver
	MainContext    *llb.State
	SourceMap      *llb.SourceMap
	TargetPlatform *ocispecs.Platform
	MetaResolver   llb.ImageMetaResolver
	LLBCaps        *apicaps.CapSet
	Warn           linter.LintWarnFunc
	AllStages      bool
}

type Dexfile2LLB interface {
	ListTargets(ctx context.Context, dt []byte) (*targets.List, error)
	Lint(ctx context.Context, dt []byte, opt ConvertOpt) (*lint.LintResults, error)
	Outline(ctx context.Context, dt []byte, opt ConvertOpt) (*outline.Outline, error)
	Compile(ctx context.Context, dt []byte, opt ConvertOpt) (st llb.State, img dockerspec.DockerOCIImage, baseImg *dockerspec.DockerOCIImage, sbom *sbom.SBOMTargets, err error)
}

type Solver interface {
	Solve(ctx context.Context) (*client.Result, error)
	Client() Client
	With(client Client, bc BuildContext) (Solver, error)
}

type Dispatcher interface {
	DispatchState(ctx context.Context, dt []byte, opt ConvertOpt) (DispatchedState, error)
}

type DispatchedState interface {
	SBOM() (*sbom.SBOMTargets, error)
	Outline(dt []byte) outline.Outline
	Resolve() (st *llb.State, img, baseImg *dockerspec.DockerOCIImage, digest digest.Digest, err error)
}
