package dex2llb

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"path"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/platforms"
	df "github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/dexnore/dexfile/sbom"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/imagemetaresolver"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/frontend/subrequests/lint"
	"github.com/moby/buildkit/frontend/subrequests/outline"
	"github.com/moby/buildkit/frontend/subrequests/targets"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/gitutil"
	"github.com/moby/buildkit/util/suggest"
	"github.com/moby/buildkit/util/system"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/patternmatcher"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

const (
	historyComment = "dexnore.dexfile.v0"

	sbomScanContext = "BUILDKIT_SBOM_SCAN_CONTEXT"
	sbomScanStage   = "BUILDKIT_SBOM_SCAN_STAGE"
)

var (
	secretsRegexpOnce  sync.Once
	secretsRegexp      *regexp.Regexp
	secretsAllowRegexp *regexp.Regexp
)

var nonEnvArgs = map[string]struct{}{
	sbomScanContext: {},
	sbomScanStage:   {},
}

func Dexfile2LLB(ctx context.Context, dt []byte, opt df.ConvertOpt) (st *llb.State, img, baseImg *dockerspec.DockerOCIImage, _ *sbom.SBOMTargets, err error) {
	ds, err := toDispatchState(ctx, dt, opt)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	sbom := &sbom.SBOMTargets{
		Core:   ds.state,
		Extras: map[string]llb.State{},
	}
	if ds.scanContext {
		sbom.Extras["context"] = ds.opt.buildContext
	}
	if ds.ignoreCache {
		sbom.IgnoreCache = true
	}
	for dsi := range allReachableStages(ds) {
		if ds != dsi && dsi.scanStage {
			sbom.Extras[dsi.stageName] = dsi.state
			if dsi.ignoreCache {
				sbom.IgnoreCache = true
			}
		}
	}

	return &ds.state, &ds.image, ds.baseImg, sbom, nil
}

func Dexfile2Outline(ctx context.Context, dt []byte, opt df.ConvertOpt) (*outline.Outline, error) {
	ds, err := toDispatchState(ctx, dt, opt)
	if err != nil {
		return nil, err
	}
	o := ds.Outline(dt)
	return &o, nil
}

func DexfileLint(ctx context.Context, dt []byte, opt df.ConvertOpt) (*lint.LintResults, error) {
	results := &lint.LintResults{}
	sourceIndex := results.AddSource(opt.SourceMap)
	opt.Warn = func(rulename, description, url, fmtmsg string, location []parser.Range) {
		results.AddWarning(rulename, description, url, fmtmsg, sourceIndex, location)
	}
	// for lint, no target means all targets
	if opt.Config.Target == "" {
		opt.AllStages = true
	}

	_, err := toDispatchState(ctx, dt, opt)

	var errLoc *parser.LocationError
	if err != nil {
		buildErr := &lint.BuildError{
			Message: err.Error(),
		}
		if errors.As(err, &errLoc) {
			ranges := mergeLocations(errLoc.Locations...)
			buildErr.Location = toPBLocation(sourceIndex, ranges)
		}
		results.Error = buildErr
	}
	return results, nil
}

func ListTargets(ctx context.Context, dt []byte) (*targets.List, error) {
	dexfile, err := parser.Parse(bytes.NewReader(dt))
	if err != nil {
		return nil, err
	}

	stages, _, err := converter.Parse(dexfile.AST, nil)
	if err != nil {
		return nil, err
	}

	l := &targets.List{
		Sources: [][]byte{dt},
	}

	for i, s := range stages {
		switch s := s.(type) {
		case *converter.Stage:
			t := targets.Target{
				Name:        s.StageName,
				Description: s.Comment,
				Default:     i == len(stages)-1,
				Base:        s.BaseName,
				Platform:    s.Platform,
				Location:    toSourceLocation(s.Location()),
			}
			l.Targets = append(l.Targets, t)
		case *converter.ImportCommand:
			t := targets.Target{
				Name:        s.StageName,
				Description: s.Comment,
				Default:     i == len(stages)-1,
				Base:        s.BaseName,
				Platform:    s.Platform,
				Location:    toSourceLocation(s.Location()),
			}
			l.Targets = append(l.Targets, t)
		}
	}
	return l, nil
}

func newRuleLinter(dt []byte, opt *df.ConvertOpt) (*linter.Linter, error) {
	var lintConfig *linter.Config
	if opt.Client != nil && opt.Client.Config().LinterConfig != nil {
		lintConfig = opt.Client.Config().LinterConfig
	} else {
		var err error
		lintOptionStr, _, _, _ := parser.ParseDirective("check", dt)
		lintConfig, err = linter.ParseLintOptions(lintOptionStr)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse check options")
		}
	}
	lintConfig.Warn = opt.Warn
	return linter.New(lintConfig), nil
}

func toDispatchState(ctx context.Context, dt []byte, opt df.ConvertOpt) (_ *dispatchState, err error) {
	if len(dt) == 0 {
		return nil, errors.Errorf("the Dexfile cannot be empty")
	}

	if opt.Client != nil && opt.MainContext != nil {
		return nil, errors.Errorf("Client and MainContext cannot both be provided")
	}

	namedContext := func(name string, copt df.ContextOpt) (df.NamedContext, error) {
		if opt.BC == nil {
			return nil, errors.Errorf("BuildClient is required to resolve named contexts")
		}
		if !strings.EqualFold(name, "scratch") && !strings.EqualFold(name, "context") {
			if copt.Platform == nil {
				copt.Platform = opt.TargetPlatform
			}
			return opt.BC.NamedContext(name, copt)
		}
		return nil, errors.Errorf("named context %q is not supported", name)
	}

	baseContext := func(name string, copt df.ContextOpt) (df.NamedContext, error) {
		if opt.BC == nil {
			return nil, errors.Errorf("BuildClient is required to resolve named contexts")
		}
		if !strings.EqualFold(name, "scratch") && !strings.EqualFold(name, "context") {
			if copt.Platform == nil {
				copt.Platform = opt.TargetPlatform
			}
			return opt.BC.BaseContext(name, copt)
		}
		return nil, errors.Errorf("base context %q is not supported", name)
	}

	lint, err := newRuleLinter(dt, &opt)
	if err != nil {
		return nil, err
	}

	if opt.Client != nil && opt.LLBCaps == nil {
		caps := opt.Client.BuildOpts().LLBCaps
		opt.LLBCaps = &caps
	}

	dexfile, err := parser.Parse(bytes.NewReader(dt))
	if err != nil {
		return nil, err
	}

	// Moby still uses the `dexfile.PrintWarnings` method to print non-empty
	// continuation line warnings. We iterate over those warnings here.
	for _, warning := range dexfile.Warnings {
		// The `dexfile.Warnings` *should* only contain warnings about empty continuation
		// lines, but we'll check the warning message to be sure, so that we don't accidentally
		// process warnings that are not related to empty continuation lines twice.
		if warning.URL == linter.RuleNoEmptyContinuation.URL {
			location := []parser.Range{*warning.Location}
			msg := linter.RuleNoEmptyContinuation.Format()
			lint.Run(&linter.RuleNoEmptyContinuation, location, msg)
		}
	}

	proxyEnv := proxyEnvFromBuildArgs(opt.Config.BuildArgs)
	stages, metaCmds, err := parseAndValidateDexfile(dexfile.AST, lint)
	if err != nil {
		return nil, err
	}
	if len(stages) == 0 {
		return nil, errors.New("dexfile contains no stages to build")
	}

	metaResolver := opt.MetaResolver
	if metaResolver == nil {
		metaResolver = imagemetaresolver.Default()
	}

	metaStageName := "busybox:latest"
	if v, ok := opt.Client.BuildOpts().Opts[df.MetaStageKey]; ok {
		metaStageName = v
	}
	platformOpt := buildPlatformOpt(&opt)
	targetName := opt.Config.Target
	if targetName == "" {
		switch st := stages[len(stages)-1].(type) {
		case *converter.Stage:
			targetName = st.StageName
		case *converter.ImportCommand:
			targetName = st.StageName
		default:
			return nil, errors.Errorf("unknown stage type %T", st)
		}
	}
	globalArgs := defaultArgs(platformOpt, opt.Config.BuildArgs, targetName)
	shlex := shell.NewLex(dexfile.EscapeToken)
	outline := newOutlineCapture()
	allDispatchStates := newDispatchStates()
	var functions = make(map[string]*converter.Function, 0)
	globalArgs, outline, err = expandAndAddDispatchState(0, converter.Stage{StageName: "meta-stage", BaseName: metaStageName, Commands: metaCmds}, expandStageOpt{
		globalArgs:        globalArgs,
		outline:           outline,
		lint:              lint,
		shlex:             shlex,
		opt:               opt,
		allDispatchStates: allDispatchStates,
		namedContext:      namedContext,
		stageName:         "meta-stage",
	})
	if err != nil {
		return nil, err
	}
	metads := allDispatchStates.states[0]
	platform := metads.platform
	if platform == nil {
		platform = &platformOpt.targetPlatform
	}
	metads.state = llb.Image(metads.BaseName(),
		dfCmd(metads.SourceCode()),
		llb.Platform(*platform),
		opt.Config.ImageResolveMode,
		llb.WithCustomName(prefixCommand(metads, "FROM "+metads.BaseName(), opt.Config.MultiPlatformRequested, platform, emptyEnvs{})),
		location(opt.SourceMap, metads.Location()),
	)
	for _, k := range globalArgs.Keys() {
		if v, ok := globalArgs.Get(k); ok {
			metads.state = metads.state.AddEnv(k, v)
		}
	}
	buildContext := &mutableDexfileOutput{}
	var dexnoreMatcher *patternmatcher.PatternMatcher
	if opt.BC != nil {
		dexnorePatterns, err := opt.BC.Dexnore(ctx)
		if err != nil {
			return nil, err
		}
		if len(dexnorePatterns) > 0 {
			dexnoreMatcher, err = patternmatcher.New(dexnorePatterns)
			if err != nil {
				return nil, err
			}
		}
	}
	dOpt := dispatchOpt{
		allDispatchStates: allDispatchStates,
		globalArgs:        globalArgs,
		buildArgValues:    opt.Config.BuildArgs,
		shlex:             shlex,
		buildContext:      llb.NewState(buildContext),
		proxyEnv:          proxyEnv,
		cacheIDNamespace:  opt.Config.CacheIDNamespace,
		buildPlatforms:    platformOpt.buildPlatforms,
		targetPlatform:    platformOpt.targetPlatform,
		extraHosts:        opt.Config.ExtraHosts,
		shmSize:           opt.Config.ShmSize,
		ulimit:            opt.Config.Ulimits,
		devices:           opt.Config.Devices,
		cgroupParent:      opt.Config.CgroupParent,
		llbCaps:           opt.LLBCaps,
		sourceMap:         opt.SourceMap,
		lint:              lint,
		dexnoreMatcher:    dexnoreMatcher,
		solver:            opt.Solver,
		buildClient:       opt.BC,
		mainContext:       opt.MainContext,
		functions:         functions,
		stageResolver: &stageResolver{
			allDispatchStates: allDispatchStates,
			namedContext:      namedContext,
			platformOpt:       platformOpt,
			metaResolver:      metaResolver,
			lint:              lint,
			opt:               opt,
		},
		convertOpt:                opt,
		mutableBuildContextOutput: buildContext,
	}

	var breakCmd = false
	metads, breakCmd, err = solveStage(ctx, metads, buildContext, dOpt)
	if err != nil {
		return nil, err
	}
	def, err := metads.state.Marshal(ctx)
	if err != nil {
		return nil, err
	}

	_, err = opt.Client.Solve(ctx, client.SolveRequest{
		Evaluate:     true,
		Definition:   def.ToPB(),
		CacheImports: opt.Config.CacheImports,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to solve meta-stage:\n%w", err)
	}

	for _, kvp := range metads.buildArgs {
		globalArgs = globalArgs.AddOrReplace(kvp.Key, kvp.ValueString())
	}

	for _, env := range metads.image.Config.Env {
		*globalArgs = globalArgs.Delete(env)
	}

	if breakCmd {
		return metads, err
	}

	validateStageNames(stages, lint)
	validateCommandCasing(stages, lint)

	// Validate that base images continue to be valid even
	// when no build arguments are used.
	validateBaseImagesWithDefaultArgs(stages, shlex, globalArgs, nil, lint)

	// set base state for every image
	for i, st := range stages {
		switch st := st.(type) {
		case *converter.Stage:
			globalArgs, outline, err = expandAndAddDispatchState(i, *st, expandStageOpt{
				globalArgs:        globalArgs,
				outline:           outline,
				lint:              lint,
				shlex:             shlex,
				opt:               opt,
				allDispatchStates: allDispatchStates,
				namedContext:      namedContext,
				stageName:         "stage",
			})
			if err != nil {
				return nil, err
			}
		case *converter.ImportCommand:
			globalArgs, outline, err = expandImportAndAddDispatchState(i, *st, expandImportOpt{
				globalArgs:        globalArgs,
				outline:           outline,
				lint:              lint,
				shlex:             shlex,
				options:           opt,
				allDispatchStates: allDispatchStates,
				namedContext:      baseContext,
				stageName:         "import",
			})
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.Errorf("unknown stage type %T", st)
		}
	}

	var target *dispatchState
	if opt.Config.Target == "" {
		target = allDispatchStates.lastTarget()
	} else {
		var ok bool
		target, ok = allDispatchStates.findStateByName(opt.Config.Target)
		if !ok {
			return nil, suggest.WrapError(errors.Errorf("target stage %q could not be found", opt.Config.Target), opt.Config.Target, allDispatchStates.names(), true)
		}
	}

	if err := fillDepsAndValidate(allDispatchStates); err != nil {
		return nil, err
	}

	if len(allDispatchStates.states) == 1 {
		allDispatchStates.states[0].stageName = ""
	}

	retDs, _, err := solveStage(ctx, target, buildContext, dOpt)
	return retDs, err
}

func toCommand(ic converter.Command, allDispatchStates *dispatchStates) (command, error) {
	cmd := command{Command: ic}
	if c, ok := ic.(*converter.CopyCommand); ok {
		if c.From != "" {
			var stn *dispatchState
			index, err := strconv.Atoi(c.From)
			if err != nil {
				stn, ok = allDispatchStates.findStateByName(c.From)
				if !ok {
					stn = &dispatchState{
						stage:        converter.Stage{BaseName: c.From, Loc: c.Location()},
						deps:         make(map[*dispatchState]converter.Command),
						paths:        make(map[string]struct{}),
						unregistered: true,
					}
				}
			} else {
				stn, err = allDispatchStates.findStateByIndex(index)
				if err != nil {
					return command{}, err
				}
			}
			cmd.sources = []*dispatchState{stn}
		}
	}

	if c, ok := ic.(*converter.CommandConatainer); ok {
		if c.From != "" {
			var stn *dispatchState
			index, err := strconv.Atoi(c.From)
			if err != nil {
				stn, ok = allDispatchStates.findStateByName(c.From)
				if !ok {
					stn = &dispatchState{
						stage:        converter.Stage{BaseName: c.From, Loc: c.Location()},
						deps:         make(map[*dispatchState]converter.Command),
						paths:        make(map[string]struct{}),
						unregistered: true,
					}
				}
			} else {
				stn, err = allDispatchStates.findStateByIndex(index)
				if err != nil {
					return command{}, err
				}
			}
			cmd.sources = []*dispatchState{stn}
		}
	}

	if ok := detectRunMount(&cmd, allDispatchStates); ok {
		return cmd, nil
	}

	return cmd, nil
}

func getEnv(state llb.State) shell.EnvGetter {
	return &envsFromState{state: &state}
}

type envsFromState struct {
	state *llb.State
	once  sync.Once
	env   shell.EnvGetter
}

func (e *envsFromState) init() {
	env, err := e.state.Env(context.TODO())
	if err != nil {
		return
	}
	e.env = env
}

func (e *envsFromState) Get(key string) (string, bool) {
	e.once.Do(e.init)
	if v, err := e.state.Value(context.TODO(), df.ScopedVariable(key)); err == nil {
		if v, ok := v.(string); ok {
			return v, true
		}
	}
	return e.env.Get(key)
}

func (e *envsFromState) Keys() []string {
	e.once.Do(e.init)
	return e.env.Keys()
}

func (ds *dispatchState) asyncLocalOpts() []llb.LocalOption {
	return filterPaths(ds.paths)
}

// init is invoked when the dispatch state inherits its attributes
// from the base image.
func (ds *dispatchState) init() {
	// mark as initialized, used to determine states that have not been dispatched yet
	if ds.base == nil {
		return
	}

	ds.state = ds.base.state
	ds.platform = ds.base.platform
	ds.image = clone(ds.base.image)
	// onbuild triggers to not carry over from base stage
	ds.image.Config.OnBuild = nil
	ds.baseImg = cloneX(ds.base.baseImg)
	// Utilize the same path index as our base image so we propagate
	// the paths we use back to the base image.
	ds.paths = ds.base.paths
	ds.workdirSet = ds.base.workdirSet
	ds.buildArgs = append(ds.buildArgs, ds.base.buildArgs...)
}

type dispatchStates struct {
	states                []*dispatchState
	immutableStates       []*dispatchState
	statesByName          map[string]*dispatchState
	immutableStatesByName map[string]*dispatchState
}

func newDispatchStates() *dispatchStates {
	return &dispatchStates{statesByName: map[string]*dispatchState{}, immutableStatesByName: map[string]*dispatchState{}}
}

func (dss *dispatchStates) names() []string {
	names := make([]string, 0, len(dss.states))
	for _, s := range dss.states {
		if s.stageName != "" {
			names = append(names, s.stageName)
		}
	}
	return names
}

func (dss *dispatchStates) addState(ds *dispatchState) {
	dss.immutableStates = append(dss.immutableStates, ds.Clone())
	dss.states = append(dss.states, ds)

	if d, ok := dss.statesByName[ds.BaseName()]; ok {
		ds.base = d
		ds.outline = d.outline.clone()
	}

	if ds.stage.StageName != "" {
		dss.immutableStatesByName[strings.ToLower(ds.stage.StageName)] = ds.Clone()
		dss.statesByName[strings.ToLower(ds.stage.StageName)] = ds
	} else if ds.imports.StageName != "" {
		dss.immutableStatesByName[strings.ToLower(ds.imports.StageName)] = ds.Clone()
		dss.statesByName[strings.ToLower(ds.imports.StageName)] = ds
	}
}

func (dss *dispatchStates) findStateByName(name string) (*dispatchState, bool) {
	ds, ok := dss.statesByName[strings.ToLower(name)]
	return ds, ok
}

func (dss *dispatchStates) findStateByIndex(index int) (*dispatchState, error) {
	if index < 0 || index >= len(dss.states) {
		return nil, errors.Errorf("invalid stage index %d", index)
	}

	return dss.states[index], nil
}

func (dss *dispatchStates) lastTarget() *dispatchState {
	return dss.states[len(dss.states)-1]
}

type command struct {
	converter.Command
	sources   []*dispatchState
	isOnBuild bool
}

// initOnBuildTriggers initializes the onbuild triggers and creates the commands and dependecies for them.
// It returns true if there were any new dependencies added that need to be resolved.
func initOnBuildTriggers(d *dispatchState, triggers []string, allDispatchStates *dispatchStates) (bool, error) {
	hasNewDeps := false
	commands := make([]command, 0, len(triggers))

	for _, trigger := range triggers {
		ast, err := parser.Parse(strings.NewReader(trigger))
		if err != nil {
			return false, err
		}
		if len(ast.AST.Children) != 1 {
			return false, errors.New("onbuild trigger should be a single expression")
		}
		node := ast.AST.Children[0]
		// reset the location to the onbuild trigger
		node.StartLine, node.EndLine = rangeStartEnd(d.Location())
		ic, err := converter.ParseCommand(ast.AST.Children[0])
		if err != nil {
			return false, err
		}
		cmd, err := toCommand(ic, allDispatchStates)
		if err != nil {
			return false, err
		}
		cmd.isOnBuild = true
		if len(cmd.sources) > 0 {
			hasNewDeps = true
		}

		commands = append(commands, cmd)

		for _, src := range cmd.sources {
			if src != nil {
				d.deps[src] = cmd
				if src.unregistered {
					allDispatchStates.addState(src)
				}
			}
		}
	}
	d.commands = append(commands, d.commands...)
	d.cmdTotal += len(commands)

	return hasNewDeps, nil
}

func pathRelativeToWorkingDir(s llb.State, p string, platform ocispecs.Platform) (string, error) {
	dir, err := s.GetDir(context.TODO(), llb.Platform(platform))
	if err != nil {
		return "", err
	}

	p, err = system.CheckSystemDriveAndRemoveDriveLetter(p, platform.OS, true)
	if err != nil {
		return "", errors.Wrap(err, "removing drive letter")
	}

	if system.IsAbs(p, platform.OS) {
		return system.NormalizePath("/", p, platform.OS, true)
	}

	// add slashes for "" and "." paths
	// "" is treated as current directory and not necessariy root
	if p == "." || p == "" {
		p = "./"
	}
	return system.NormalizePath(dir, p, platform.OS, true)
}

func addEnv(env []string, k, v string) []string {
	gotOne := false
	for i, envVar := range env {
		key, _ := parseKeyValue(envVar)
		if shell.EqualEnvKeys(key, k) {
			env[i] = k + "=" + v
			gotOne = true
			break
		}
	}
	if !gotOne {
		env = append(env, k+"="+v)
	}
	return env
}

func parseKeyValue(env string) (string, string) {
	parts := strings.SplitN(env, "=", 2)
	v := ""
	if len(parts) > 1 {
		v = parts[1]
	}

	return parts[0], v
}

func dfCmd(cmd any) llb.ConstraintsOpt {
	// TODO: add fmt.Stringer to converter.Command to remove interface{}
	var cmdStr string
	if cmd, ok := cmd.(fmt.Stringer); ok {
		cmdStr = cmd.String()
	}
	if cmd, ok := cmd.(string); ok {
		cmdStr = cmd
	}
	return llb.WithDescription(map[string]string{
		"com.dexnore.dexfile.v1.command": cmdStr,
	})
}

func runCommandString(args []string, buildArgs []converter.KeyValuePairOptional, env shell.EnvGetter) string {
	var tmpBuildEnv []string
	tmpIdx := map[string]int{}
	for _, arg := range buildArgs {
		v, ok := env.Get(arg.Key)
		if !ok {
			v = arg.ValueString()
		}
		if idx, ok := tmpIdx[arg.Key]; ok {
			tmpBuildEnv[idx] = arg.Key + "=" + v
		} else {
			tmpIdx[arg.Key] = len(tmpBuildEnv)
			tmpBuildEnv = append(tmpBuildEnv, arg.Key+"="+v)
		}
	}
	if len(tmpBuildEnv) > 0 {
		tmpBuildEnv = append([]string{fmt.Sprintf("|%d", len(tmpBuildEnv))}, tmpBuildEnv...)
	}

	return strings.Join(append(tmpBuildEnv, args...), " ")
}

func commitToHistory(img *dockerspec.DockerOCIImage, msg string, withLayer bool, st *llb.State, tm *time.Time) error {
	if st != nil {
		msg += " # buildkit"
	}

	img.History = append(img.History, ocispecs.History{
		CreatedBy:  msg,
		Comment:    historyComment,
		EmptyLayer: !withLayer,
		Created:    tm,
	})
	return nil
}

func allReachableStages(s *dispatchState) map[*dispatchState]struct{} {
	stages := make(map[*dispatchState]struct{})
	addReachableStages(s, stages)
	return stages
}

func addReachableStages(s *dispatchState, stages map[*dispatchState]struct{}) {
	if _, ok := stages[s]; ok {
		return
	}
	stages[s] = struct{}{}
	if s.base != nil {
		addReachableStages(s.base, stages)
	}
	for d := range s.deps {
		addReachableStages(d, stages)
	}
}

func validateCopySourcePath(src string, cfg *copyConfig) error {
	if cfg.ignoreMatcher == nil {
		return nil
	}
	cmd := "Copy"
	if cfg.isAddCommand {
		cmd = "Add"
	}

	ok, err := cfg.ignoreMatcher.MatchesOrParentMatches(src)
	if err != nil {
		return err
	}
	if ok {
		msg := linter.RuleCopyIgnoredFile.Format(cmd, src)
		cfg.opt.lint.Run(&linter.RuleCopyIgnoredFile, cfg.location, msg)
	}

	return nil
}

func validateCircularDependency(states []*dispatchState) error {
	var visit func(*dispatchState, []converter.Command) []converter.Command
	if states == nil {
		return nil
	}
	visited := make(map[*dispatchState]struct{})
	path := make(map[*dispatchState]struct{})

	visit = func(state *dispatchState, current []converter.Command) []converter.Command {
		_, ok := visited[state]
		if ok {
			return nil
		}
		visited[state] = struct{}{}
		path[state] = struct{}{}
		for dep, c := range state.deps {
			next := append(current, c)
			if _, ok := path[dep]; ok {
				return next
			}
			if c := visit(dep, next); c != nil {
				return c
			}
		}
		delete(path, state)
		return nil
	}
	for _, state := range states {
		if cmds := visit(state, nil); cmds != nil {
			err := errors.Errorf("circular dependency detected on stage: %s", state.stageName)
			for _, c := range cmds {
				err = parser.WithLocation(err, c.Location())
			}
			return err
		}
	}
	return nil
}

func normalizeContextPaths(paths map[string]struct{}) []string {
	// Avoid a useless allocation if the set of paths is empty.
	if len(paths) == 0 {
		return nil
	}

	pathSlice := make([]string, 0, len(paths))
	for p := range paths {
		if p == "/" {
			return nil
		}
		pathSlice = append(pathSlice, path.Join(".", p))
	}

	slices.Sort(pathSlice)
	return pathSlice
}

// filterPaths returns the local options required to filter an llb.Local
// to only the required paths.
func filterPaths(paths map[string]struct{}) []llb.LocalOption {
	if includePaths := normalizeContextPaths(paths); len(includePaths) > 0 {
		return []llb.LocalOption{llb.FollowPaths(includePaths)}
	}
	return nil
}

func proxyEnvFromBuildArgs(args map[string]string) *llb.ProxyEnv {
	pe := &llb.ProxyEnv{}
	isNil := true
	for k, v := range args {
		if strings.EqualFold(k, "http_proxy") {
			pe.HTTPProxy = v
			isNil = false
		}
		if strings.EqualFold(k, "https_proxy") {
			pe.HTTPSProxy = v
			isNil = false
		}
		if strings.EqualFold(k, "ftp_proxy") {
			pe.FTPProxy = v
			isNil = false
		}
		if strings.EqualFold(k, "no_proxy") {
			pe.NoProxy = v
			isNil = false
		}
		if strings.EqualFold(k, "all_proxy") {
			pe.AllProxy = v
			isNil = false
		}
	}
	if isNil {
		return nil
	}
	return pe
}

type mutableDexfileOutput struct {
	llb.Output
}

func withShell(img dockerspec.DockerOCIImage, args []string) []string {
	var shell []string
	if len(img.Config.Shell) > 0 {
		shell = slices.Clone(img.Config.Shell)
	} else {
		shell = defaultShell(img.OS)
	}
	return append(shell, strings.Join(args, " "))
}

func autoDetectPlatform(img dockerspec.DockerOCIImage, target ocispecs.Platform, supported []ocispecs.Platform) ocispecs.Platform {
	os := img.OS
	arch := img.Architecture
	if target.OS == os && target.Architecture == arch {
		return target
	}
	for _, p := range supported {
		if p.OS == os && p.Architecture == arch {
			return p
		}
	}
	return target
}

func uppercaseCmd(str string) string {
	p := strings.SplitN(str, " ", 2)
	p[0] = strings.ToUpper(p[0])
	return strings.Join(p, " ")
}

func processCmdEnv(shlex *shell.Lex, cmd string, env shell.EnvGetter) string {
	w, _, err := shlex.ProcessWord(cmd, env)
	if err != nil {
		return cmd
	}
	return w
}

func prefixCommand(ds *dispatchState, str string, prefixPlatform bool, platform *ocispecs.Platform, env shell.EnvGetter) string {
	if ds.cmdTotal == 0 {
		return str
	}
	out := "["
	if prefixPlatform && platform != nil {
		out += platforms.FormatAll(*platform) + formatTargetPlatform(*platform, platformFromEnv(env)) + " "
	}
	if ds.stageName != "" {
		out += ds.stageName + " "
	}
	ds.cmdIndex++
	out += fmt.Sprintf("%*d/%d] ", int(1+math.Log10(float64(ds.cmdTotal))), ds.cmdIndex, ds.cmdTotal)
	if ds.cmdIsOnBuild {
		out += "ONBUILD "
	}
	return out + str
}

// formatTargetPlatform formats a secondary platform string for cross compilation cases
func formatTargetPlatform(base ocispecs.Platform, target *ocispecs.Platform) string {
	if target == nil {
		return ""
	}
	if target.OS == "" {
		target.OS = base.OS
	}
	if target.Architecture == "" {
		target.Architecture = base.Architecture
	}
	p := platforms.Normalize(*target)

	if p.OS == base.OS && p.Architecture != base.Architecture {
		archVariant := p.Architecture
		if p.Variant != "" {
			archVariant += "/" + p.Variant
		}
		return "->" + archVariant
	}
	if p.OS != base.OS {
		return "->" + platforms.FormatAll(p)
	}
	return ""
}

// platformFromEnv returns defined platforms based on TARGET* environment variables
func platformFromEnv(env shell.EnvGetter) *ocispecs.Platform {
	var p ocispecs.Platform
	var set bool
	for _, key := range env.Keys() {
		switch key {
		case "TARGETPLATFORM":
			v, _ := env.Get(key)
			p, err := platforms.Parse(v)
			if err != nil {
				continue
			}
			return &p
		case "TARGETOS":
			p.OS, _ = env.Get(key)
			set = true
		case "TARGETARCH":
			p.Architecture, _ = env.Get(key)
			set = true
		case "TARGETVARIANT":
			p.Variant, _ = env.Get(key)
			set = true
		}
	}
	if !set {
		return nil
	}
	return &p
}

func location(sm *llb.SourceMap, locations []parser.Range) llb.ConstraintsOpt {
	loc := make([]*pb.Range, 0, len(locations))
	for _, l := range locations {
		loc = append(loc, &pb.Range{
			Start: &pb.Position{
				Line:      int32(l.Start.Line),
				Character: int32(l.Start.Character),
			},
			End: &pb.Position{
				Line:      int32(l.End.Line),
				Character: int32(l.End.Character),
			},
		})
	}
	return sm.Location(loc)
}

func summarizeHeredoc(doc string) string {
	doc = strings.TrimSpace(doc)
	lines := strings.Split(strings.ReplaceAll(doc, "\r\n", "\n"), "\n")
	summary := lines[0]
	if len(lines) > 1 {
		summary += "..."
	}
	return summary
}

func commonImageNames() []string {
	repos := []string{
		"alpine", "busybox", "centos", "debian", "golang", "ubuntu", "fedora",
	}
	out := make([]string, 0, len(repos)*4)
	for _, name := range repos {
		out = append(out, name, "docker.io/library"+name, name+":latest", "docker.io/library"+name+":latest")
	}
	return out
}

func isHTTPSource(src string) bool {
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		return false
	}
	return !isGitSource(src)
}

func isGitSource(src string) bool {
	// https://github.com/ORG/REPO.git is a git source, not an http source
	if gitRef, gitErr := gitutil.ParseGitRef(src); gitRef != nil && gitErr == nil {
		return true
	}
	return false
}

func isEnabledForStage(stage string, value string) bool {
	if enabled, err := strconv.ParseBool(value); err == nil {
		return enabled
	}

	vv := strings.Split(value, ",")
	return slices.Contains(vv, stage)
}

func isSelfConsistentCasing(s string) bool {
	return s == strings.ToLower(s) || s == strings.ToUpper(s)
}

func validateCaseMatch(name string, isMajorityLower bool, location []parser.Range, lint *linter.Linter) {
	var correctCasing string
	if isMajorityLower && strings.ToLower(name) != name {
		correctCasing = "lowercase"
	} else if !isMajorityLower && strings.ToUpper(name) != name {
		correctCasing = "uppercase"
	}
	if correctCasing != "" {
		msg := linter.RuleConsistentInstructionCasing.Format(name, correctCasing)
		lint.Run(&linter.RuleConsistentInstructionCasing, location, msg)
	}
}

func validateCommandCasing(stages []converter.Adder, lint *linter.Linter) {
	var lowerCount, upperCount int
	caseCount := func(origCmd string, cmds []converter.Command) {
		if isSelfConsistentCasing(origCmd) {
			if strings.ToLower(origCmd) == origCmd {
				lowerCount++
			} else {
				upperCount++
			}
		}
		for _, cmd := range cmds {
			cmdName := cmd.Name()
			if isSelfConsistentCasing(cmdName) {
				if strings.ToLower(cmdName) == cmdName {
					lowerCount++
				} else {
					upperCount++
				}
			}
		}
	}
	for _, stage := range stages {
		switch stage := stage.(type) {
		case *converter.Stage:
			caseCount(stage.OrigCmd, stage.Commands)
		case *converter.ImportCommand:
			caseCount(stage.OrigCmd, stage.Commands)
		}
	}

	isMajorityLower := lowerCount > upperCount
	for _, stage := range stages {
		// Here, we check both if the command is consistent per command (ie, "CMD" or "cmd", not "Cmd")
		// as well as ensuring that the casing is consistent throughout the dockerfile by comparing the
		// command to the casing of the majority of commands.
		switch stage := stage.(type) {
		case *converter.Stage:
			validateCaseMatch(stage.OrigCmd, isMajorityLower, stage.Location(), lint)
			for _, cmd := range stage.Commands {
				validateCaseMatch(cmd.Name(), isMajorityLower, cmd.Location(), lint)
			}
		case *converter.ImportCommand:
			validateCaseMatch(stage.OrigCmd, isMajorityLower, stage.Location(), lint)
			for _, cmd := range stage.Commands {
				validateCaseMatch(cmd.Name(), isMajorityLower, cmd.Location(), lint)
			}
		}
	}
}

var reservedStageNames = map[string]struct{}{
	"context": {},
	"scratch": {},
}

func validateStageNames(stages []converter.Adder, lint *linter.Linter) {
	stageNames := make(map[string]struct{})
	for _, stage := range stages {
		switch stage := stage.(type) {
		case *converter.Stage:
			if _, ok := reservedStageNames[stage.StageName]; ok && stage.StageName != "" {
				msg := linter.RuleReservedStageName.Format(stage.StageName)
				lint.Run(&linter.RuleReservedStageName, stage.Location(), msg)
			}

			if _, ok := stageNames[stage.StageName]; ok {
				msg := linter.RuleDuplicateStageName.Format(stage.StageName)
				lint.Run(&linter.RuleDuplicateStageName, stage.Location(), msg)
			}
			stageNames[stage.StageName] = struct{}{}
		case *converter.ImportCommand:
			if _, ok := reservedStageNames[stage.StageName]; ok && stage.StageName != "" {
				msg := linter.RuleReservedStageName.Format(stage.StageName)
				lint.Run(&linter.RuleReservedStageName, stage.Location(), msg)
			}

			if _, ok := stageNames[stage.StageName]; ok {
				msg := linter.RuleDuplicateStageName.Format(stage.StageName)
				lint.Run(&linter.RuleDuplicateStageName, stage.Location(), msg)
			}
			stageNames[stage.StageName] = struct{}{}
		}
	}
}

func reportUnmatchedVariables(cmd converter.Command, buildArgs []converter.KeyValuePairOptional, env shell.EnvGetter, unmatched map[string]struct{}, opt *dispatchOpt) {
	if len(unmatched) == 0 {
		return
	}
	for _, buildArg := range buildArgs {
		delete(unmatched, buildArg.Key)
	}
	if len(unmatched) == 0 {
		return
	}
	options := env.Keys()
	for cmdVar := range unmatched {
		if _, nonEnvOk := nonEnvArgs[cmdVar]; nonEnvOk {
			continue
		}
		match, _ := suggest.Search(cmdVar, options, runtime.GOOS != "windows")
		msg := linter.RuleUndefinedVar.Format(cmdVar, match)
		opt.lint.Run(&linter.RuleUndefinedVar, cmd.Location(), msg)
	}
}

func mergeLocations(locations ...[]parser.Range) []parser.Range {
	allRanges := []parser.Range{}
	for _, ranges := range locations {
		allRanges = append(allRanges, ranges...)
	}
	if len(allRanges) == 0 {
		return []parser.Range{}
	}
	if len(allRanges) == 1 {
		return allRanges
	}

	slices.SortFunc(allRanges, func(a, b parser.Range) int {
		return a.Start.Line - b.Start.Line
	})

	location := []parser.Range{}
	currentRange := allRanges[0]
	for _, r := range allRanges[1:] {
		if r.Start.Line <= currentRange.End.Line {
			currentRange.End.Line = max(currentRange.End.Line, r.End.Line)
		} else {
			location = append(location, currentRange)
			currentRange = r
		}
	}
	location = append(location, currentRange)
	return location
}

func toPBLocation(sourceIndex int, location []parser.Range) pb.Location {
	loc := make([]*pb.Range, 0, len(location))
	for _, l := range location {
		loc = append(loc, &pb.Range{
			Start: &pb.Position{
				Line:      int32(l.Start.Line),
				Character: int32(l.Start.Character),
			},
			End: &pb.Position{
				Line:      int32(l.End.Line),
				Character: int32(l.End.Character),
			},
		})
	}
	return pb.Location{
		SourceIndex: int32(sourceIndex),
		Ranges:      loc,
	}
}

func unusedFromArgsCheckKeys(env shell.EnvGetter, args map[string]argInfo) map[string]struct{} {
	matched := make(map[string]struct{})
	for _, arg := range args {
		matched[arg.definition.Key] = struct{}{}
	}
	for _, k := range env.Keys() {
		matched[k] = struct{}{}
	}
	return matched
}

func reportUnusedFromArgs(testArgKeys map[string]struct{}, unmatched map[string]struct{}, location []parser.Range, lint *linter.Linter) {
	var argKeys []string
	for arg := range testArgKeys {
		argKeys = append(argKeys, arg)
	}
	for arg := range unmatched {
		if _, ok := testArgKeys[arg]; ok {
			continue
		}
		suggest, _ := suggest.Search(arg, argKeys, true)
		msg := linter.RuleUndefinedArgInFrom.Format(arg, suggest)
		lint.Run(&linter.RuleUndefinedArgInFrom, location, msg)
	}
}

func reportRedundantTargetPlatform(platformVar string, nameMatch shell.ProcessWordResult, location []parser.Range, env shell.EnvGetter, lint *linter.Linter) {
	// Only match this rule if there was only one matched name.
	// It's psosible there were multiple args and that one of them expanded to an empty
	// string and we don't want to report a warning when that happens.
	if len(nameMatch.Matched) == 1 && len(nameMatch.Unmatched) == 0 {
		const targetPlatform = "TARGETPLATFORM"
		// If target platform is the only environment variable that was substituted and the result
		// matches the target platform exactly, we can infer that the input was ${TARGETPLATFORM} or
		// $TARGETPLATFORM.
		if _, ok := nameMatch.Matched[targetPlatform]; !ok {
			return
		}

		if result, _ := env.Get(targetPlatform); nameMatch.Result == result {
			msg := linter.RuleRedundantTargetPlatform.Format(platformVar)
			lint.Run(&linter.RuleRedundantTargetPlatform, location, msg)
		}
	}
}

func reportConstPlatformDisallowed(stageName string, nameMatch shell.ProcessWordResult, location []parser.Range, lint *linter.Linter) {
	if len(nameMatch.Matched) > 0 || len(nameMatch.Unmatched) > 0 {
		// Some substitution happened so the platform was not a constant.
		// Disable checking for this warning.
		return
	}

	// Attempt to parse the platform result. If this fails, then it will fail
	// later so just ignore.
	p, err := platforms.Parse(nameMatch.Result)
	if err != nil {
		return
	}

	// Check if the platform os or architecture is used in the stage name
	// at all. If it is, then disable this warning.
	if strings.Contains(stageName, p.OS) || strings.Contains(stageName, p.Architecture) {
		return
	}

	// Report the linter warning.
	msg := linter.RuleFromPlatformFlagConstDisallowed.Format(nameMatch.Result)
	lint.Run(&linter.RuleFromPlatformFlagConstDisallowed, location, msg)
}

type instructionTracker struct {
	Loc   []parser.Range
	IsSet bool
}

func (v *instructionTracker) MarkUsed(loc []parser.Range) {
	v.Loc = loc
	v.IsSet = true
}

func validateUsedOnce(c converter.Command, loc *instructionTracker, lint *linter.Linter) {
	if loc.IsSet {
		msg := linter.RuleMultipleInstructionsDisallowed.Format(c.Name())
		// Report the location of the previous invocation because it is the one
		// that will be ignored.
		lint.Run(&linter.RuleMultipleInstructionsDisallowed, loc.Loc, msg)
	}
	loc.MarkUsed(c.Location())
}

func wrapSuggestAny(err error, keys map[string]struct{}, options []string) error {
	for k := range keys {
		var ok bool
		ok, err = suggest.WrapErrorMaybe(err, k, options, true)
		if ok {
			break
		}
	}
	return err
}

func validateBaseImagePlatform(name string, expected, actual ocispecs.Platform, location []parser.Range, lint *linter.Linter) {
	if expected.OS != actual.OS || expected.Architecture != actual.Architecture {
		expectedStr := platforms.FormatAll(platforms.Normalize(expected))
		actualStr := platforms.FormatAll(platforms.Normalize(actual))
		msg := linter.RuleInvalidBaseImagePlatform.Format(name, expectedStr, actualStr)
		lint.Run(&linter.RuleInvalidBaseImagePlatform, location, msg)
	}
}

func getSecretsRegex() (*regexp.Regexp, *regexp.Regexp) {
	// Check for either full value or first/last word.
	// Examples: api_key, DATABASE_PASSWORD, GITHUB_TOKEN, secret_MESSAGE, AUTH
	// Case insensitive.
	secretsRegexpOnce.Do(func() {
		secretTokens := []string{
			"apikey",
			"auth",
			"credential",
			"credentials",
			"key",
			"password",
			"pword",
			"passwd",
			"secret",
			"token",
		}
		pattern := `(?i)(?:_|^)(?:` + strings.Join(secretTokens, "|") + `)(?:_|$)`
		secretsRegexp = regexp.MustCompile(pattern)

		allowTokens := []string{
			"public",
		}
		allowPattern := `(?i)(?:_|^)(?:` + strings.Join(allowTokens, "|") + `)(?:_|$)`
		secretsAllowRegexp = regexp.MustCompile(allowPattern)
	})
	return secretsRegexp, secretsAllowRegexp
}

func validateNoSecretKey(instruction, key string, location []parser.Range, lint *linter.Linter) {
	deny, allow := getSecretsRegex()
	if deny.MatchString(key) && !allow.MatchString(key) {
		msg := linter.RuleSecretsUsedInArgOrEnv.Format(instruction, key)
		lint.Run(&linter.RuleSecretsUsedInArgOrEnv, location, msg)
	}
}

func validateBaseImagesWithDefaultArgs(stages []converter.Adder, shlex *shell.Lex, env *llb.EnvList, argCmds []converter.ArgCommand, lint *linter.Linter) {
	// Build the arguments as if no build options were given
	// and using only defaults.
	args, _, err := buildMetaArgs(env, shlex, argCmds, nil)
	if err != nil {
		// Abandon running the linter. We'll likely fail after this point
		// with the same error but we shouldn't error here inside
		// of the linting check.
		return
	}

	for _, st := range stages {
		switch st := st.(type) {
		case *converter.ImportCommand:
			vv := strings.SplitN(st.BaseName, ":", 2)
			baseName := st.BaseName
			supported := false
			if slices.Contains(supportedImportPrefixes, vv[0]) {
				supported = true
				baseName = vv[1]
			}
			if !supported {
				nameMatch, err := shlex.ProcessWordWithMatches(baseName, args)
				if err != nil {
					return
				}

				// Verify the image spec is potentially valid.
				if _, err := reference.ParseNormalizedNamed(nameMatch.Result); err != nil {
					msg := linter.RuleInvalidDefaultArgInFrom.Format(baseName)
					lint.Run(&linter.RuleInvalidDefaultArgInFrom, st.Location(), msg)
				}
			}
		case *converter.Stage:
			nameMatch, err := shlex.ProcessWordWithMatches(st.BaseName, args)
			if err != nil {
				return
			}

			// Verify the image spec is potentially valid.
			if _, err := reference.ParseNormalizedNamed(nameMatch.Result); err != nil {
				msg := linter.RuleInvalidDefaultArgInFrom.Format(st.BaseName)
				lint.Run(&linter.RuleInvalidDefaultArgInFrom, st.Location(), msg)
			}
		}
	}
}

func buildMetaArgs(args *llb.EnvList, shlex *shell.Lex, argCommands []converter.ArgCommand, buildArgs map[string]string) (*llb.EnvList, map[string]argInfo, error) {
	allArgs := make(map[string]argInfo)

	for _, cmd := range argCommands {
		for _, kp := range cmd.Args {
			info := argInfo{definition: kp, location: cmd.Location()}
			if v, ok := buildArgs[kp.Key]; !ok {
				if kp.Value != nil {
					result, err := shlex.ProcessWordWithMatches(*kp.Value, args)
					if err != nil {
						return nil, nil, parser.WithLocation(err, cmd.Location())
					}

					kp.Value = &result.Result
					info.deps = result.Matched
					if _, ok := result.Matched[kp.Key]; ok {
						delete(info.deps, kp.Key)
						if old, ok := allArgs[kp.Key]; ok {
							for k := range old.deps {
								if info.deps == nil {
									info.deps = make(map[string]struct{})
								}
								info.deps[k] = struct{}{}
							}
						}
					}
				}
			} else {
				kp.Value = &v
			}
			if kp.Value != nil {
				args = args.AddOrReplace(kp.Key, *kp.Value)
				info.value = *kp.Value
			} else if cmd.Required {
				return args, allArgs, parser.WithLocation(errors.Errorf("missing required argument %q", kp.Key), cmd.Location())
			}
			allArgs[kp.Key] = info
		}
	}
	return args, allArgs, nil
}

func rangeStartEnd(r []parser.Range) (int, int) {
	if len(r) == 0 {
		return 0, 0
	}
	start := math.MaxInt32
	end := 0
	for _, rng := range r {
		if rng.Start.Line < start {
			start = rng.Start.Line
		}
		if rng.End.Line > end {
			end = rng.End.Line
		}
	}
	return start, end
}

type emptyEnvs struct{}

func (emptyEnvs) Get(string) (string, bool) {
	return "", false
}

func (emptyEnvs) Keys() []string {
	return nil
}
