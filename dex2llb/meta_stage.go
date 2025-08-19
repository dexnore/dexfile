package dex2llb

import (
	"fmt"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
)

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
