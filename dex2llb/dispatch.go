package dex2llb

import (
	"context"
	"path"
	"path/filepath"
	"strings"

	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/patternmatcher"
	"github.com/pkg/errors"
)

type Dispatcher func(d *dispatchState, cmd command, opt dispatchOpt) error

func dispatch(ctx context.Context, d *dispatchState, cmd command, opt dispatchOpt) (err error) {
	d.cmdIsOnBuild = cmd.isOnBuild
	// ARG command value could be ignored, so defer handling the expansion error
	_, isArg := cmd.Command.(*converter.ArgCommand)
	if ex, ok := cmd.Command.(converter.SupportsSingleWordExpansion); ok && !isArg {
		err := ex.Expand(func(word string) (string, error) {
			env := getEnv(d.state)
			newword, unmatched, err := opt.shlex.ProcessWord(word, env)
			reportUnmatchedVariables(cmd, d.buildArgs, env, unmatched, &opt)
			return newword, err
		})
		if err != nil {
			return err
		}
	}
	if ex, ok := cmd.Command.(converter.SupportsSingleWordExpansionRaw); ok {
		err := ex.ExpandRaw(func(word string) (string, error) {
			lex := shell.NewLex('\\')
			lex.SkipProcessQuotes = true
			env := getEnv(d.state)
			newword, unmatched, err := lex.ProcessWord(word, env)
			reportUnmatchedVariables(cmd, d.buildArgs, env, unmatched, &opt)
			return newword, err
		})
		if err != nil {
			return err
		}
	}

	switch c := cmd.Command.(type) {
	case *converter.MaintainerCommand:
		err = dispatchMaintainer(d, c)
	case *converter.EnvCommand:
		err = dispatchEnv(d, c, opt.lint)
	case *converter.RunCommand:
		err = dispatchRun(d, c, opt.proxyEnv, cmd.sources, opt)
	case *converter.WorkdirCommand:
		err = dispatchWorkdir(d, c, true, &opt)
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
		})
		if err == nil {
			for _, src := range c.SourcePaths {
				if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
					d.ctxPaths[path.Join("/", filepath.ToSlash(src))] = struct{}{}
				}
			}
		}
	case *converter.LabelCommand:
		err = dispatchLabel(d, c, opt.lint)
	case *converter.OnbuildCommand:
		err = dispatchOnbuild(d, c)
	case *converter.CmdCommand:
		err = dispatchCmd(d, c, opt.lint)
	case *converter.EntrypointCommand:
		err = dispatchEntrypoint(d, c, opt.lint)
	case *converter.HealthCheckCommand:
		err = dispatchHealthcheck(d, c, opt.lint)
	case *converter.ExposeCommand:
		err = dispatchExpose(d, c, opt.shlex)
	case *converter.UserCommand:
		err = dispatchUser(d, c, true)
	case *converter.VolumeCommand:
		err = dispatchVolume(d, c)
	case *converter.StopSignalCommand:
		err = dispatchStopSignal(d, c)
	case *converter.ShellCommand:
		err = dispatchShell(d, c)
	case *converter.ArgCommand:
		err = dispatchArg(d, c, &opt)
	case *converter.CopyCommand:
		l := opt.buildContext
		var ignoreMatcher *patternmatcher.PatternMatcher
		if len(cmd.sources) != 0 {
			src := cmd.sources[0]
			if !src.dispatched {
				return errors.Errorf("cannot copy from stage %q, it needs to be defined before current stage %q", c.From, d.stageName)
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
		})
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
	case *converter.CommandExec:
		def, err := d.state.Marshal(ctx)
		if err != nil {
			return parser.WithLocation(err, cmd.Location())
		}

		res, err := opt.solver.Client().Solve(ctx, client.SolveRequest{
			Evaluate:     true,
			Definition:   def.ToPB(),
			CacheImports: opt.solver.Client().Config().CacheImports,
		})
		if err != nil {
			return parser.WithLocation(err, cmd.Location())
		}
		return dispatchExec(ctx, d, *c, res, opt)
	case *converter.ConditionIfElse:
		err = handleIfElse(ctx, d, *c, func(nc []converter.Command) error {
			for _, cmd := range nc {
				cmd, err := toCommand(cmd, opt.allDispatchStates)
				if err != nil {
					return err
				}
				if err := dispatch(ctx, d, cmd, opt); err != nil {
					return err
				}
			}
			return nil
		}, opt)
	case *converter.CommandFor:
		err = handleForLoop(ctx, d, *c, func(nc []converter.Command, s string) error {
			for _, cmd := range nc {
				d.state = d.state.AddEnv(c.As, s)
				cmd, err := toCommand(cmd, opt.allDispatchStates)
				if err != nil {
					return err
				}
				if err := dispatch(ctx, d, cmd, opt); err != nil {
					return err
				}
			}
			return nil
		}, opt)
	case *converter.CommandConatainer:
		err = dispatchCtr(ctx, d, *c, opt)
	case *converter.Function:
		err = dispatchFunction(ctx, d, *c, opt)
	case *converter.CommandBuild:
		d, err = dispatchBuild(*c, opt)
	default:
		return &converter.UnknownInstructionError{Instruction: c.Name(), Line: c.Location()[0].Start.Line}
	}
	return err
}
