package dex2llb

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/containerd/platforms"
	"github.com/dexnore/dexfile"
	instructions "github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/apicaps"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/patternmatcher"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

type dispatchState struct {
	opt          dispatchOpt
	state        llb.State
	image        dockerspec.DockerOCIImage
	namedContext dexfile.NamedContext
	platform     *ocispecs.Platform
	stage        instructions.Stage
	imports      instructions.ImportCommand
	base         *dispatchState
	baseImg      *dockerspec.DockerOCIImage // immutable, unlike image
	dispatched   bool
	resolved     bool // resolved is set to true if base image has been resolved
	onBuildInit  bool
	deps         map[*dispatchState]instructions.Command
	buildArgs    []instructions.KeyValuePairOptional
	commands     []command
	// ctxPaths marks the paths this dispatchState uses from the build context.
	ctxPaths map[string]struct{}
	// paths marks the paths that are used by this dispatchState.
	paths          map[string]struct{}
	ignoreCache    bool
	unregistered   bool
	stageName      string
	cmdIndex       int
	cmdIsOnBuild   bool
	cmdTotal       int
	prefixPlatform bool
	outline        outlineCapture
	epoch          *time.Time
	scanStage      bool
	scanContext    bool
	// workdirSet is set to true if a workdir has been set
	// within the current dexfile.
	workdirSet bool

	entrypoint  instructionTracker
	cmd         instructionTracker
	healthcheck instructionTracker
}

func (ds dispatchState) Location() []parser.Range {
	if len(ds.stage.Location()) > 0 {
		return ds.stage.Location()
	}

	return ds.imports.Location()
}

func (ds *dispatchState) StageCommands() []instructions.Command {
	if len(ds.stage.Commands) > 0 {
		return ds.stage.Commands
	}

	return ds.imports.Commands
}

func (ds *dispatchState) SetBaseName(name string) {
	if ds.stage.BaseName != "" {
		ds.stage.BaseName = name
	} else {
		ds.imports.BaseName = name
	}
}

func (ds *dispatchState) BaseName() string {
	if ds.stage.BaseName != "" {
		return ds.stage.BaseName
	}

	return ds.imports.BaseName
}

func (ds *dispatchState) SourceCode() string {
	if ds.stage.SourceCode != "" {
		return ds.stage.SourceCode
	}

	return ds.imports.SourceCode
}

func (ds dispatchState) Clone() *dispatchState {
	var base *dispatchState
	if ds.base != nil {
		base = ds.base.Clone()
	}

	var epoch *time.Time
	if ds.epoch != nil {
		e := *ds.epoch
		epoch = &e
	}

	var platform *ocispecs.Platform
	if ds.platform != nil {
		p := platforms.MustParse(platforms.Format(*ds.platform))
		platform = &p
	}

	st := ds.state
	dir, err := st.GetDir(context.TODO())
	if err != nil || dir == "" {
		st = st.Dir("/")
	}

	return &dispatchState{
		dispatched:     ds.dispatched,
		base:           base,
		stageName:      ds.stageName,
		state:          st,
		outline:        ds.outline.clone(),
		ctxPaths:       maps.Clone(ds.ctxPaths),
		stage:          ds.stage,
		imports:        ds.imports,
		deps:           maps.Clone(ds.deps),
		paths:          maps.Clone(ds.paths),
		unregistered:   ds.unregistered,
		image:          clone(ds.image),
		buildArgs:      slices.Clone(ds.buildArgs),
		epoch:          epoch,
		cmd:            ds.cmd,
		entrypoint:     ds.entrypoint,
		healthcheck:    ds.healthcheck,
		platform:       platform,
		prefixPlatform: ds.prefixPlatform,
		ignoreCache:    ds.ignoreCache,
		cmdIndex:       ds.cmdIndex,
		cmdTotal:       ds.cmdTotal,
		cmdIsOnBuild:   ds.cmdIsOnBuild,
		workdirSet:     ds.workdirSet,
		opt:            ds.opt,
		namedContext:   ds.namedContext,
		baseImg:        cloneX(ds.baseImg),
		resolved:       ds.resolved,
		onBuildInit:    ds.onBuildInit,
		commands:       slices.Clone(ds.commands),
		scanStage:      ds.scanStage,
		scanContext:    ds.scanContext,
	}
}

type dispatchOpt struct {
	allDispatchStates *dispatchStates
	functions         map[string]*instructions.Function
	globalArgs        shell.EnvGetter
	buildArgValues    map[string]string
	shlex             *shell.Lex
	buildContext      llb.State
	proxyEnv          *llb.ProxyEnv
	cacheIDNamespace  string
	targetPlatform    ocispecs.Platform
	buildPlatforms    []ocispecs.Platform
	extraHosts        []llb.HostIP
	shmSize           int64
	ulimit            []*pb.Ulimit
	devices           []*pb.CDIDevice
	cgroupParent      string
	llbCaps           *apicaps.CapSet
	sourceMap         *llb.SourceMap
	lint              *linter.Linter
	dexnoreMatcher    *patternmatcher.PatternMatcher
	solver            dexfile.Solver
	buildClient       dexfile.BuildClient
	mainContext       *llb.State
	stageResolver     *stageResolver
	convertOpt		  dexfile.ConvertOpt
	mutableBuildContextOutput *mutableDexfileOutput
}

func (o dispatchOpt) Clone() dispatchOpt {
	var shlex *shell.Lex
	if o.shlex != nil {
		s := *o.shlex
		shlex = &s
	}

	var sourcemap *llb.SourceMap
	if o.sourceMap != nil {
		sm := llb.SourceMap{
			Data:     slices.Clone(o.sourceMap.Data),
			Filename: o.sourceMap.Filename,
			Language: o.sourceMap.Language,
		}
		if o.sourceMap.Definition != nil {
			def := llb.Definition{}
			def.FromPB(o.sourceMap.Definition.ToPB().CloneVT())
			sm.Definition = &def
		}
		if o.sourceMap.State != nil {
			st := llb.NewState(o.sourceMap.State.Output())
			sm.State = &st
		}
		sourcemap = &sm
	}

	var dss *dispatchStates
	if o.allDispatchStates != nil {
		ds := o.allDispatchStates.Clone()
		dss = &ds
	}

	var mainContext *llb.State
	if o.mainContext != nil {
		st := *o.mainContext
		mainContext = &st
	}

	return dispatchOpt{
		lint:              o.lint,
		buildArgValues:    maps.Clone(o.buildArgValues),
		globalArgs:        o.globalArgs,
		shlex:             shlex,
		targetPlatform:    o.targetPlatform,
		sourceMap:         sourcemap,
		llbCaps:           o.llbCaps,
		dexnoreMatcher:    o.dexnoreMatcher,
		ulimit:            slices.Clone(o.ulimit),
		devices:           slices.Clone(o.devices),
		proxyEnv:          o.proxyEnv,
		extraHosts:        slices.Clone(o.extraHosts),
		shmSize:           o.shmSize,
		cgroupParent:      o.cgroupParent,
		buildContext:      o.buildContext,
		cacheIDNamespace:  o.cacheIDNamespace,
		allDispatchStates: dss,
		buildPlatforms:    slices.Clone(o.buildPlatforms),
		solver:            o.solver,
		buildClient:       o.buildClient,
		mainContext:       mainContext,
		functions:         maps.Clone(o.functions),
		stageResolver: o.stageResolver,
		convertOpt: o.convertOpt,
		mutableBuildContextOutput: o.mutableBuildContextOutput,
	}
}

func (dss dispatchStates) Clone() dispatchStates {
	states, statesByName := dispatchStateCloneStates(dss.states, dss.statesByName) 
	immutableStates, immutableStatesByName := dispatchStateCloneStates(dss.immutableStates, dss.immutableStatesByName)
	return dispatchStates{
		states:       states,
		statesByName: statesByName,
		immutableStates: immutableStates,
		immutableStatesByName: immutableStatesByName,
	}
}

func dispatchStateCloneStates(ds []*dispatchState, dss map[string]*dispatchState) ([]*dispatchState, map[string]*dispatchState) {
	var ds_clone = make([]*dispatchState, len(ds))
	var dss_clone = make(map[string]*dispatchState, len(dss))

	for k, v := range dss {
		if v == nil {
			dss_clone[k] = nil
			continue
		}
		dss_clone[k] = v.Clone()
		for i, p := range ds {
			if p == v {
				ds_clone[i] = dss_clone[k]
				break
			}
		}
	}
	for i, p := range ds_clone {
		if p == nil {
			ds_clone[i] = ds[i].Clone()
		}
	}

	return ds_clone, dss_clone
}
