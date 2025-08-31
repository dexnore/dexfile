package dex2llb

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/patternmatcher"
	"github.com/pkg/errors"
)

type Dispatcher func(d *dispatchState, cmd command, opt dispatchOpt) error

func dispatch(ctx context.Context, d *dispatchState, cmd command, opt dispatchOpt, copts ...llb.ConstraintsOpt) (breakCmd bool, err error) {
	d.cmdIsOnBuild = cmd.isOnBuild
	// ARG command value could be ignored, so defer handling the expansion error
	_, isArg := cmd.Command.(*converter.ArgCommand)
	if ex, ok := cmd.Command.(converter.SupportsSingleWordExpansion); ok && !isArg {
		err := ex.Expand(func(word string) (string, error) {
			shlex := opt.shlex
			shlex.SkipUnsetEnv = true
			env := getEnv(d.state)
			newword, unmatched, err := shlex.ProcessWord(word, env)
			reportUnmatchedVariables(cmd, d.buildArgs, env, unmatched, &opt)
			return newword, err
		})
		if err != nil {
			return false, err
		}
	}
	if ex, ok := cmd.Command.(converter.SupportsSingleWordExpansionRaw); ok {
		err := ex.ExpandRaw(func(word string) (string, error) {
			lex := shell.NewLex('\\')
			lex.SkipProcessQuotes = true
			lex.SkipUnsetEnv = true
			env := getEnv(d.state)
			newword, unmatched, err := lex.ProcessWord(word, env)
			reportUnmatchedVariables(cmd, d.buildArgs, env, unmatched, &opt)
			return newword, err
		})
		if err != nil {
			return false, err
		}
	}

	switch c := cmd.Command.(type) {
	case *converter.MaintainerCommand:
		err = dispatchMaintainer(d, c, copts...)
	case *converter.EnvCommand:
		err = dispatchEnv(d, c, opt.lint, copts...)
	case *converter.RunCommand:
		err = dispatchRun(d, c, opt.proxyEnv, cmd.sources, opt, copts...)
	case *converter.WorkdirCommand:
		err = dispatchWorkdir(d, c, true, &opt, copts...)
	case *converter.AddCommand:
		err = dispatchCopy(d, copyConfig{
			params:          c.SourcesAndDest,
			excludePatterns: c.ExcludePatterns,
			source:          opt.buildContext,
			isAddCommand:    true,
			cmdToPrint:      c,
			chown:           c.Chown,
			chmod:           c.Chmod,
			link:            c.Link,
			keepGitDir:      c.KeepGitDir,
			checksum:        c.Checksum,
			unpack:          c.Unpack,
			location:        c.Location(),
			ignoreMatcher:   opt.dexnoreMatcher,
			opt:             opt,
		}, copts...)
		if err == nil {
			for _, src := range c.SourcePaths {
				if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
					d.ctxPaths[path.Join("/", filepath.ToSlash(src))] = struct{}{}
				}
			}
		}
	case *converter.LabelCommand:
		err = dispatchLabel(d, c, opt.lint, copts...)
	case *converter.OnbuildCommand:
		err = dispatchOnbuild(d, c, copts...)
	case *converter.CmdCommand:
		err = dispatchCmd(d, c, opt.lint, copts...)
	case *converter.EntrypointCommand:
		err = dispatchEntrypoint(d, c, opt.lint, copts...)
	case *converter.HealthCheckCommand:
		err = dispatchHealthcheck(d, c, opt.lint, copts...)
	case *converter.ExposeCommand:
		err = dispatchExpose(d, c, opt.shlex, copts...)
	case *converter.UserCommand:
		err = dispatchUser(d, c, true, copts...)
	case *converter.VolumeCommand:
		err = dispatchVolume(d, c, copts...)
	case *converter.StopSignalCommand:
		err = dispatchStopSignal(d, c, copts...)
	case *converter.ShellCommand:
		err = dispatchShell(d, c, copts...)
	case *converter.ArgCommand:
		err = dispatchArg(d, c, &opt, copts...)
	case *converter.CopyCommand:
		l := opt.buildContext
		var ignoreMatcher *patternmatcher.PatternMatcher
		if len(cmd.sources) != 0 {
			src := cmd.sources[0]
			if !src.dispatched {
				return false, errors.Errorf("cannot copy from stage %q, it needs to be defined before current stage %q", c.From, d.stageName)
			}
			l = src.state
		} else {
			ignoreMatcher = opt.dexnoreMatcher
		}
		err = dispatchCopy(d, copyConfig{
			params:          c.SourcesAndDest,
			excludePatterns: c.ExcludePatterns,
			source:          l,
			isAddCommand:    false,
			cmdToPrint:      c,
			chown:           c.Chown,
			chmod:           c.Chmod,
			link:            c.Link,
			parents:         c.Parents,
			location:        c.Location(),
			ignoreMatcher:   ignoreMatcher,
			opt:             opt,
		}, copts...)
		if err == nil {
			if len(cmd.sources) == 0 {
				for _, src := range c.SourcePaths {
					d.ctxPaths[path.Join("/", filepath.ToSlash(src))] = struct{}{}
				}
			} else {
				source := cmd.sources[0]
				if source.paths == nil {
					source.paths = make(map[string]struct{})
				}
				for _, src := range c.SourcePaths {
					source.paths[path.Join("/", filepath.ToSlash(src))] = struct{}{}
				}
			}
		}
		return false, err
	case *converter.CommandExec:
		var res = c.Result
		if c.Result == nil {
			def, err := d.state.Marshal(ctx, copts...)
			if err != nil {
				return false, parser.WithLocation(err, cmd.Location())
			}

			res, err = opt.solver.Client().Solve(ctx, client.SolveRequest{
				Evaluate:     true,
				Definition:   def.ToPB(),
				CacheImports: opt.solver.Client().Config().CacheImports,
			})
			if err != nil {
				return false, parser.WithLocation(err, cmd.Location())
			}
		}
		err = dispatchExec(ctx, d, *c, res, opt, copts...)
	case *converter.ConditionIfElse:
		return handleIfElse(ctx, d, *c, func(nc []converter.Command, copts ...llb.ConstraintsOpt) (bool, error) {
			for _, cmd := range nc {
				ic, err := toCommand(cmd, opt.allDispatchStates)
				if err != nil {
					return false, parser.WithLocation(err, cmd.Location())
				}
				var breakCmd bool
				if breakCmd, err = dispatch(ctx, d, ic, opt, copts...); err != nil {
					return breakCmd, parser.WithLocation(err, cmd.Location())
				}
				if breakCmd {
					return true, nil
				}
			}
			return false, nil
		}, opt, copts...)
	case *converter.CommandFor:
		return handleForLoop(ctx, d, *c, func(nc []converter.Command, copts ...llb.ConstraintsOpt) (bool, error) {
			for _, cmd := range nc {
				cmd, err := toCommand(cmd, opt.allDispatchStates)
				if err != nil {
					return false, parser.WithLocation(err, cmd.Location())
				}
				if breakCmd, err = dispatch(ctx, d, cmd, opt, copts...); err != nil {
					return breakCmd, parser.WithLocation(err, cmd.Location())
				}
				if breakCmd {
					return true, nil
				}
			}
			return false, nil
		}, opt, copts...)
	case *converter.CommandConatainer:
		return dispatchCtr(ctx, d, *c, opt, copts...)
	case *converter.Function:
		return dispatchFunction(ctx, d, *c, opt, copts...)
	case *converter.CommandBuild:
		d, err = dispatchBuild(ctx, *c, opt, copts...)
		return true, err
	default:
		return false, fmt.Errorf("unknown dispatcher command: %w", &converter.UnknownInstructionError{Instruction: c.Name(), Line: c.Location()[0].Start.Line})
	}

	return false, err
}
