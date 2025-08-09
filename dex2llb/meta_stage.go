package dex2llb

import (
	"context"
	"fmt"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/pkg/errors"
)

type metaresolverOpt struct {
	i                 int
	shlex             *shell.Lex
	options           dexfile.ConvertOpt
	pOpt              platformOpt
	lint              *linter.Linter
	proxy             *llb.ProxyEnv
	allDispatchStates *dispatchStates
	stage             converter.Stage
	functions 		  []converter.Function
	namedContext      func(name string, copt dexfile.ContextOpt) (dexfile.NamedContext, error)
	baseContext       func(name string, copt dexfile.ContextOpt) (dexfile.NamedContext, error)
}

func resolveMetaCmds(cmd converter.Command, argCommands []converter.ArgCommand, globalArgs *llb.EnvList, outline outlineCapture, state llb.State, opts metaresolverOpt) (metaArgs []converter.ArgCommand, functions []converter.Function,  _ *llb.EnvList, _ outlineCapture, _ llb.State, err error) {
	dupOpt := dispatchOpt{
		allDispatchStates: opts.allDispatchStates,
		buildArgValues:    opts.options.Config.BuildArgs,
		shlex:             opts.shlex,
		globalArgs:        globalArgs,
		proxyEnv:          opts.proxy,
		cacheIDNamespace:  opts.options.Config.CacheIDNamespace,
		buildPlatforms:    opts.pOpt.buildPlatforms,
		targetPlatform:    opts.pOpt.targetPlatform,
		extraHosts:        opts.options.Config.ExtraHosts,
		shmSize:           opts.options.Config.ShmSize,
		ulimit:            opts.options.Config.Ulimits,
		devices:           opts.options.Config.Devices,
		cgroupParent:      opts.options.Config.CgroupParent,
		llbCaps:           opts.options.LLBCaps,
		sourceMap:         opts.options.SourceMap,
		lint:              opts.lint,
		solver:            opts.options.Solver,
	}

	dupD := &dispatchState{
		stage:    opts.stage,
		state:    state,
		outline:  outline,
		deps:     make(map[*dispatchState]converter.Command),
		epoch:    opts.options.Config.Epoch,
		platform: opts.options.TargetPlatform,
		opt:      dupOpt,
		image:    emptyImage(*platformFromEnv(globalArgs)),
	}

	globalArgs, outline.allArgs, err = buildMetaArgs(globalArgs, opts.shlex, argCommands, opts.options.Config.BuildArgs)
	if err != nil {
		return nil, nil, nil, outline, state, err
	}

	switch cmd := cmd.(type) {
	case *converter.ArgCommand:
		metaArgs = append(metaArgs, *cmd)
	case *converter.Stage:
		globalArgs, outline, err = expandAndAddDispatchState(opts.i, *cmd, expandStageOpt{
			globalArgs:        globalArgs,
			outline:           outline,
			lint:              opts.lint,
			shlex:             opts.shlex,
			opt:               opts.options,
			allDispatchStates: opts.allDispatchStates,
			namedContext:      opts.namedContext,
			stageName:         "meta",
		})
		if err != nil {
			return nil, nil, nil, outline, state, err
		}
	case *converter.ImportCommand:
		globalArgs, outline, err = expandImportAndAddDispatchState(opts.i, *cmd, expandImportOpt{
			globalArgs:        globalArgs,
			outline:           outline,
			lint:              opts.lint,
			shlex:             opts.shlex,
			options:           opts.options,
			allDispatchStates: opts.allDispatchStates,
			namedContext:      opts.baseContext,
			stageName:         "meta",
		})
		if err != nil {
			return nil, nil, nil, outline, state, err
		}
	case *converter.ConditionIfElse:
		err := handleIfElse(context.Background(), dupD, *cmd, func(cmds []converter.Command) error {
			for _, c := range cmds {
				var condArgs = make([]converter.ArgCommand, 0)
				var fun []converter.Function
				opts.functions = append(opts.functions, functions...)
				condArgs, fun, globalArgs, outline, state, err = resolveMetaCmds(c, argCommands, globalArgs, outline, state, opts)
				if err != nil {
					return err
				}

				functions = append(functions, fun...)
				metaArgs = append(metaArgs, condArgs...)
				globalArgs, outline.allArgs, err = buildMetaArgs(globalArgs, opts.shlex, argCommands, opts.options.Config.BuildArgs)
				if err != nil {
					return err
				}
			}

			globalArgs, outline.allArgs, err = buildMetaArgs(globalArgs, opts.shlex, argCommands, opts.options.Config.BuildArgs)
			return err
		}, dupD.opt)
		if err != nil {
			return nil, nil, nil, outline, state, err
		}
	case *converter.Function:
		if cmd == nil {
			return nil, nil, nil, outline, state, errors.New("nil function")
		}
		functions = append(functions, *cmd)
	default:
		return nil, nil, nil, outline, state, errors.Errorf("unsupported meta arg %T", cmd)
	}

	return metaArgs, functions, globalArgs, outline, state, nil
}

type expandStageOpt struct {
	stageName         string
	globalArgs        *llb.EnvList
	outline           outlineCapture
	lint              *linter.Linter
	shlex             *shell.Lex
	opt               dexfile.ConvertOpt
	allDispatchStates *dispatchStates
	namedContext      func(name string, copt dexfile.ContextOpt) (dexfile.NamedContext, error)
}

func expandAndAddDispatchState(i int, st converter.Stage, opts expandStageOpt) (*llb.EnvList, outlineCapture, error) {
	ds, err := expandStage(st, opts.globalArgs, opts.outline, opts.lint, opts.shlex)
	if err != nil {
		return nil, opts.outline, err
	}

	ds = &dispatchState{
		stage:          ds.stage,
		outline:        ds.outline,
		deps:           make(map[*dispatchState]converter.Command),
		ctxPaths:       make(map[string]struct{}),
		paths:          make(map[string]struct{}),
		stageName:      st.StageName,
		prefixPlatform: opts.opt.Config.MultiPlatformRequested,
		epoch:          opts.opt.Config.Epoch,
	}

	if st.StageName != "" {
		nc, err := opts.namedContext(st.StageName, dexfile.ContextOpt{
			Platform:       ds.platform,
			ResolveMode:    opts.opt.Config.ImageResolveMode.String(),
			AsyncLocalOpts: ds.asyncLocalOpts,
		})
		if err != nil {
			return nil, opts.outline, err
		}
		if nc != nil {
			ds.namedContext = nc
			opts.allDispatchStates.addState(ds)
			ds.base = nil                             // reset base set by addState
			return opts.globalArgs, opts.outline, nil // continue
		}
	}

	if st.StageName == "" {
		ds.stageName = fmt.Sprintf("%s-%d", opts.stageName, i)
	}

	opts.allDispatchStates.addState(ds)

	total := 0
	if ds.stage.BaseName != dexfile.EmptyImageName && ds.base == nil {
		total = 1
	}
	for _, cmd := range ds.stage.Commands {
		switch cmd.(type) {
		case *converter.AddCommand, *converter.CopyCommand, *converter.RunCommand:
			total++
		case *converter.WorkdirCommand:
			total++
		}
	}
	ds.cmdTotal = total
	if opts.opt.Client != nil {
		ds.ignoreCache = opts.opt.Client.IsNoCache(st.StageName)
	}

	return opts.globalArgs, ds.outline, nil
}

type expandImportOpt struct {
	stageName         string
	globalArgs        *llb.EnvList
	outline           outlineCapture
	lint              *linter.Linter
	shlex             *shell.Lex
	options           dexfile.ConvertOpt
	allDispatchStates *dispatchStates
	namedContext      func(name string, copt dexfile.ContextOpt) (dexfile.NamedContext, error)
}

func expandImportAndAddDispatchState(i int, st converter.ImportCommand, opts expandImportOpt) (*llb.EnvList, outlineCapture, error) {
	ds, err := expandImport(st, opts.globalArgs, opts.outline, opts.lint, opts.shlex)
	if err != nil {
		return nil, opts.outline, err
	}

	ds = &dispatchState{
		imports:        ds.imports,
		outline:        ds.outline,
		deps:           make(map[*dispatchState]converter.Command),
		ctxPaths:       make(map[string]struct{}),
		paths:          make(map[string]struct{}),
		stageName:      st.StageName,
		prefixPlatform: opts.options.Config.MultiPlatformRequested,
		epoch:          opts.options.Config.Epoch,
	}

	if st.BaseName != "" {
		nc, err := opts.namedContext(st.BaseName, dexfile.ContextOpt{
			Platform:       ds.platform,
			ResolveMode:    opts.options.Config.ImageResolveMode.String(),
			AsyncLocalOpts: ds.asyncLocalOpts,
		})
		if err != nil {
			return nil, opts.outline, err
		}
		if nc != nil {
			ds.namedContext = nc
			opts.allDispatchStates.addState(ds)
			ds.base = nil // reset base set by addState
			return opts.globalArgs, opts.outline, nil
		}
	}

	if st.StageName == "" {
		ds.stageName = fmt.Sprintf("%s-%d", opts.stageName, i)
	}

	opts.allDispatchStates.addState(ds)

	total := 0
	if ds.imports.BaseName != dexfile.EmptyImageName && ds.base == nil {
		total = 1
	}
	for _, cmd := range ds.imports.Commands {
		switch cmd.(type) {
		case *converter.AddCommand, *converter.CopyCommand, *converter.RunCommand:
			total++
		case *converter.WorkdirCommand:
			total++
		}
	}
	ds.cmdTotal = total
	if opts.options.Client != nil {
		ds.ignoreCache = opts.options.Client.IsNoCache(st.StageName)
	}

	return opts.globalArgs, opts.outline, nil
}
