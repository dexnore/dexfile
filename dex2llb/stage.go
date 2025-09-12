package dex2llb

import (
	"context"
	"maps"
	"slices"

	"github.com/containerd/platforms"
	"github.com/dexnore/dexfile/context/maincontext"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/moby/buildkit/util/system"
)

func solveStage(ctx context.Context, target *dispatchState, buildContext *mutableDexfileOutput, opt dispatchOpt) (_ *dispatchState, breakCmd bool, err error) {
	var platformOpt = buildPlatformOpt(&opt.convertOpt)

	allReachable, err := resolveReachableStage(ctx, opt.allDispatchStates, target, opt.stageResolver)
	if err != nil {
		return nil, false, err
	}
	ctxPaths := map[string]struct{}{}
	for _, d := range opt.allDispatchStates.states {
		if !opt.convertOpt.AllStages {
			if _, ok := allReachable[d]; !ok || d.dispatched {
				continue
			}
		}
		d.init()
		d.dispatched = true

		// Ensure platform is set.
		if d.platform == nil {
			d.platform = &d.opt.targetPlatform
		}

		// make sure that PATH is always set
		if _, ok := shell.EnvsFromSlice(d.image.Config.Env).Get("PATH"); !ok {
			var osName string
			if d.platform != nil {
				osName = d.platform.OS
			}
			// except for Windows, leave that to the OS. #5445
			if osName != "windows" {
				d.image.Config.Env = append(d.image.Config.Env, "PATH="+system.DefaultPathEnv(osName))
			}
		}

		// initialize base metadata from image conf
		for _, env := range d.image.Config.Env {
			k, v := parseKeyValue(env)
			d.state = d.state.AddEnv(k, v)
		}
		if opt.convertOpt.Config.Hostname != "" {
			d.state = d.state.Hostname(opt.convertOpt.Config.Hostname)
		}
		if d.image.Config.WorkingDir != "" {
			if err = dispatchWorkdir(d, &converter.WorkdirCommand{Path: d.image.Config.WorkingDir}, false, nil); err != nil {
				return nil, false, parser.WithLocation(err, d.Location())
			}
		}
		if d.image.Config.User != "" {
			if err = dispatchUser(d, &converter.UserCommand{User: d.image.Config.User}, false); err != nil {
				return nil, false, parser.WithLocation(err, d.Location())
			}
		}

		d.state = d.state.Network(opt.convertOpt.Config.NetworkMode)
		d.opt = opt
		for _, cmd := range d.commands {
			if breakCmd, err = dispatch(ctx, d, cmd, opt); err != nil {
				err = parser.WithLocation(err, cmd.Location())
				return d, breakCmd, err
			}
			if breakCmd {
				return d, true, nil
			}
		}

		for p := range d.ctxPaths {
			ctxPaths[p] = struct{}{}
		}

		for _, name := range []string{sbomScanContext, sbomScanStage} {
			var b bool
			if v, ok := d.opt.globalArgs.Get(name); ok {
				b = isEnabledForStage(d.stageName, v)
			}
			for _, kv := range d.buildArgs {
				if kv.Key == name && kv.Value != nil {
					b = isEnabledForStage(d.stageName, *kv.Value)
				}
			}
			if b {
				if name == sbomScanContext {
					d.scanContext = true
				} else {
					d.scanStage = true
				}
			}
		}
	}

	// Ensure the entirety of the target state is marked as used.
	// This is done after we've already evaluated every stage to ensure
	// the paths attribute is set correctly.
	target.paths["/"] = struct{}{}

	if len(opt.convertOpt.Config.Labels) != 0 && target.image.Config.Labels == nil {
		target.image.Config.Labels = make(map[string]string, len(opt.convertOpt.Config.Labels))
	}
	maps.Copy(target.image.Config.Labels, opt.convertOpt.Config.Labels)

	// If lint.Error() returns an error, it means that
	// there were warnings, and that our linter has been
	// configured to return an error on warnings,
	// so we appropriately return that error here.
	if err := opt.lint.Error(); err != nil {
		return nil, false, err
	}

	opts := filterPaths(ctxPaths)
	bctx := opt.convertOpt.MainContext
	if opt.convertOpt.BC != nil {
		bctx, err = opt.convertOpt.BC.MainContext(ctx, opts...)
		if err != nil {
			return nil, breakCmd, err
		}
	} else if bctx == nil {
		bctx = maincontext.DefaultMainContext(opts...)
	}
	buildContext.Output = bctx.Output()

	defaults := []llb.ConstraintsOpt{
		llb.Platform(platformOpt.targetPlatform),
	}
	if opt.convertOpt.LLBCaps != nil {
		defaults = append(defaults, llb.WithCaps(*opt.convertOpt.LLBCaps))
	}
	target.state = target.state.SetMarshalDefaults(defaults...)

	if !platformOpt.implicitTarget {
		sameOsArch := platformOpt.targetPlatform.OS == target.image.OS && platformOpt.targetPlatform.Architecture == target.image.Architecture
		target.image.OS = platformOpt.targetPlatform.OS
		target.image.Architecture = platformOpt.targetPlatform.Architecture
		if platformOpt.targetPlatform.Variant != "" || !sameOsArch {
			target.image.Variant = platformOpt.targetPlatform.Variant
		}
		if platformOpt.targetPlatform.OSVersion != "" || !sameOsArch {
			target.image.OSVersion = platformOpt.targetPlatform.OSVersion
		}
		if platformOpt.targetPlatform.OSFeatures != nil {
			target.image.OSFeatures = slices.Clone(platformOpt.targetPlatform.OSFeatures)
		}
	}
	target.image.Platform = platforms.Normalize(target.image.Platform)
	return target, false, nil
}
