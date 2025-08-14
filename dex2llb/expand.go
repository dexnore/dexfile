package dex2llb

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/containerd/platforms"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/pkg/errors"
)

func expandStage(st converter.Stage, globalArgs shell.EnvGetter, outline outlineCapture, lint *linter.Linter, shlex *shell.Lex) (ds *dispatchState, err error) {
	var used map[string]struct{}
	ds = &dispatchState{stage: st}
	ds.stage.BaseName, used, err = expandStageBaseName(st, globalArgs, outline.allArgs, lint, shlex)
	if err != nil {
		return nil, err
	}

	var usedArgs map[string]struct{}
	if ds.stage.Platform != "" {
		ds.stage.Platform, usedArgs, err = expandStagePlatform(st, globalArgs, outline.allArgs, lint, shlex)
		if err != nil {
			return nil, parser.WithLocation(fmt.Errorf("failed to expand stage platform: %w", err), st.Location())
		}

		p, err := platforms.Parse(ds.stage.Platform)
		if err != nil {
			return nil, parser.WithLocation(fmt.Errorf("failed to parse expanded stage platform: %w", err), st.Location())
		}
		ds.platform = &p
	}

	maps.Copy(used, usedArgs)

	if ds.stage.Context != "" {
		ds.stage.Context, usedArgs, err = expandStageContext(st, globalArgs, outline.allArgs, lint, shlex)
		if err != nil {
			return nil, parser.WithLocation(fmt.Errorf("failed to expand stage context: %w", err), st.Location())
		}
		maps.Copy(used, usedArgs)
	}

	ds.outline = outline.clone()
	maps.Copy(ds.outline.usedArgs, used)
	return ds, nil
}

func expandImport(st converter.ImportCommand, globalArgs shell.EnvGetter, outline outlineCapture, lint *linter.Linter, shlex *shell.Lex) (ds *dispatchState, err error) {
	var used map[string]struct{}
	ds = &dispatchState{imports: st}
	ds.imports.BaseName, used, err = expandImportBaseName(st, globalArgs, outline.allArgs, lint, shlex)
	if err != nil {
		return nil, err
	}

	var usedArgs map[string]struct{}
	if ds.stage.Platform != "" {
		ds.imports.Platform, usedArgs, err = expandImportPlatform(st, globalArgs, outline.allArgs, lint, shlex)
		if err != nil {
			return nil, parser.WithLocation(fmt.Errorf("failed to expand import name: %w", err), st.Location())
		}

		p, err := platforms.Parse(ds.stage.Platform)
		if err != nil {
			return nil, parser.WithLocation(fmt.Errorf("failed to parse expanded import platform: %w", err), st.Location())
		}
		ds.platform = &p
	}

	maps.Copy(used, usedArgs)

	if ds.imports.Target != "" {
		ds.imports.Target, usedArgs, err = expandImportTarget(st, globalArgs, outline.allArgs, lint, shlex)
		if err != nil {
			return nil, parser.WithLocation(fmt.Errorf("failed to expand import target: %w", err), st.Location())
		}
		maps.Copy(used, usedArgs)
	}

	if ds.imports.FileName != "" {
		ds.imports.FileName, usedArgs, err = expandImportFilename(st, globalArgs, outline.allArgs, lint, shlex)
		if err != nil {
			return nil, parser.WithLocation(fmt.Errorf("failed to expand import filename: %w", err), st.Location())
		}
		maps.Copy(used, usedArgs)
	}

	ds.outline = outline.clone()
	maps.Copy(ds.outline.usedArgs, used)
	return ds, nil
}

func expandStageBaseName(st converter.Stage, globalArgs shell.EnvGetter, args map[string]argInfo, lint *linter.Linter, shlex *shell.Lex) (string, map[string]struct{}, error) {
	nameMatch, err := shlex.ProcessWordWithMatches(st.BaseName, globalArgs)
	argKeys := unusedFromArgsCheckKeys(globalArgs, args)
	reportUnusedFromArgs(argKeys, nameMatch.Unmatched, st.Location(), lint)

	if nameMatch.Matched == nil {
		nameMatch.Matched = map[string]struct{}{}
	}

	if err != nil {
		return "", nil, parser.WithLocation(err, st.Location())
	}
	if nameMatch.Result == "" {
		return "", nil, parser.WithLocation(errors.Errorf("base name (%s) should not be blank", st.BaseName), st.Location())
	}

	return nameMatch.Result, nameMatch.Matched, nil
}

var supportedImportPrefixes = []string{
	"docker-image",
	"git",
	"http", "https",
	"oci-layout",
	"local",
	"input",
}

func expandImportBaseName(st converter.ImportCommand, globalArgs shell.EnvGetter, args map[string]argInfo, lint *linter.Linter, shlex *shell.Lex) (string, map[string]struct{}, error) {
	vv := strings.SplitN(st.BaseName, ":", 2)
	baseName := st.BaseName
	supported := false
	if slices.Contains(supportedImportPrefixes, vv[0]) {
		supported = true
		baseName = vv[1]
	}
	nameMatch, err := shlex.ProcessWordWithMatches(baseName, globalArgs)
	argKeys := unusedFromArgsCheckKeys(globalArgs, args)
	reportUnusedFromArgs(argKeys, nameMatch.Unmatched, st.Location(), lint)
	if nameMatch.Matched == nil {
		nameMatch.Matched = map[string]struct{}{}
	}

	if err != nil {
		return "", nil, parser.WithLocation(err, st.Location())
	}
	if nameMatch.Result == "" {
		return "", nil, parser.WithLocation(errors.Errorf("base name (%s) should not be blank", st.BaseName), st.Location())
	}

	if supported {
		nameMatch.Result = vv[0] + ":" + nameMatch.Result
	}

	return nameMatch.Result, nameMatch.Matched, nil
}

func expandImportTarget(cmd converter.ImportCommand, globalArgs shell.EnvGetter, args map[string]argInfo, lint *linter.Linter, shlex *shell.Lex) (string, map[string]struct{}, error) {
	nameMatch, err := shlex.ProcessWordWithMatches(cmd.Target, globalArgs)
	argKeys := unusedFromArgsCheckKeys(globalArgs, args)
	reportUnusedFromArgs(argKeys, nameMatch.Unmatched, cmd.Location(), lint)

	if err != nil {
		return "", nil, parser.WithLocation(err, cmd.Location())
	}

	if cmd.Target != "" {
		return nameMatch.Result, nameMatch.Matched, nil
	}

	return "", nil, parser.WithLocation(errors.Errorf("target (%s) should not be blank", cmd.Target), cmd.Location())
}

func expandStagePlatform(st converter.Stage, globalArgs shell.EnvGetter, args map[string]argInfo, lint *linter.Linter, shlex *shell.Lex) (string, map[string]struct{}, error) {
	platMatch, err := shlex.ProcessWordWithMatches(st.Platform, globalArgs)
	argKeys := unusedFromArgsCheckKeys(globalArgs, args)
	reportUnusedFromArgs(argKeys, platMatch.Unmatched, st.Location(), lint)
	reportRedundantTargetPlatform(st.Platform, platMatch, st.Location(), globalArgs, lint)
	reportConstPlatformDisallowed(st.StageName, platMatch, st.Location(), lint)

	if err != nil {
		return "", nil, parser.WithLocation(errors.Wrapf(err, "failed to process arguments for platform %s", platMatch.Result), st.Location())
	}

	if st.Platform == "" {
		return platMatch.Result, platMatch.Matched, nil
	}

	if platMatch.Result == "" {
		err := errors.Errorf("empty platform value from expression %s", st.Platform)
		err = parser.WithLocation(err, st.Location())
		err = wrapSuggestAny(err, platMatch.Unmatched, globalArgs.Keys())
		return "", nil, err
	}

	_, err = platforms.Parse(platMatch.Result)
	if err != nil {
		err = parser.WithLocation(err, st.Location())
		err = wrapSuggestAny(err, platMatch.Unmatched, globalArgs.Keys())
		return "", nil, parser.WithLocation(errors.Wrapf(err, "failed to parse platform %s", st.Platform), st.Location())
	}

	return platMatch.Result, platMatch.Matched, nil
}

func expandImportPlatform(st converter.ImportCommand, globalArgs shell.EnvGetter, args map[string]argInfo, lint *linter.Linter, shlex *shell.Lex) (string, map[string]struct{}, error) {
	platMatch, err := shlex.ProcessWordWithMatches(st.Platform, globalArgs)
	argKeys := unusedFromArgsCheckKeys(globalArgs, args)
	reportUnusedFromArgs(argKeys, platMatch.Unmatched, st.Location(), lint)
	reportRedundantTargetPlatform(st.Platform, platMatch, st.Location(), globalArgs, lint)
	reportConstPlatformDisallowed(st.StageName, platMatch, st.Location(), lint)

	if err != nil {
		return "", nil, parser.WithLocation(errors.Wrapf(err, "failed to process arguments for platform %s", platMatch.Result), st.Location())
	}

	if st.Platform == "" {
		return platMatch.Result, platMatch.Matched, nil
	}

	if platMatch.Result == "" {
		err := errors.Errorf("empty platform value from expression %s", st.Platform)
		err = parser.WithLocation(err, st.Location())
		err = wrapSuggestAny(err, platMatch.Unmatched, globalArgs.Keys())
		return "", nil, err
	}

	_, err = platforms.Parse(platMatch.Result)
	if err != nil {
		err = parser.WithLocation(err, st.Location())
		err = wrapSuggestAny(err, platMatch.Unmatched, globalArgs.Keys())
		return "", nil, parser.WithLocation(errors.Wrapf(err, "failed to parse platform %s", st.Platform), st.Location())
	}

	return platMatch.Result, platMatch.Matched, nil
}

func expandStageContext(st converter.Stage, globalArgs shell.EnvGetter, args map[string]argInfo, lint *linter.Linter, shlex *shell.Lex) (string, map[string]struct{}, error) {
	ctxMatch, err := shlex.ProcessWordWithMatches(st.Context, globalArgs)
	argKeys := unusedFromArgsCheckKeys(globalArgs, args)
	reportUnusedFromArgs(argKeys, ctxMatch.Unmatched, st.Location(), lint)

	if err != nil {
		return "", nil, parser.WithLocation(errors.Wrapf(err, "failed to process arguments for platform %s", ctxMatch.Result), st.Location())
	}

	return ctxMatch.Result, ctxMatch.Matched, nil
}

func expandImportFilename(st converter.ImportCommand, globalArgs shell.EnvGetter, args map[string]argInfo, lint *linter.Linter, shlex *shell.Lex) (string, map[string]struct{}, error) {
	ctxMatch, err := shlex.ProcessWordWithMatches(st.FileName, globalArgs)
	argKeys := unusedFromArgsCheckKeys(globalArgs, args)
	reportUnusedFromArgs(argKeys, ctxMatch.Unmatched, st.Location(), lint)

	if err != nil {
		return "", nil, parser.WithLocation(errors.Wrapf(err, "failed to process arguments for platform %s", ctxMatch.Result), st.Location())
	}

	return ctxMatch.Result, ctxMatch.Matched, nil
}
