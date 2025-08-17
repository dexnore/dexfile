package converter

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dexnore/dexfile/instructions/parser"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

var excludePatternsEnabled = false
var parentsEnabled = false

var parseRunPreHooks []func(*RunCommand, parseRequest) error
var parseRunPostHooks []func(*RunCommand, parseRequest) error

func parseKvps(args []string, cmdName string) (KeyValuePairs, error) {
	if len(args) == 0 {
		return nil, errAtLeastOneArgument(cmdName)
	}
	if len(args)%3 != 0 {
		// should never get here, but just in case
		return nil, errTooManyArguments(cmdName)
	}
	var res KeyValuePairs
	for j := 0; j < len(args); j += 3 {
		if len(args[j]) == 0 {
			return nil, errBlankCommandNames(cmdName)
		}
		name, value, delim := args[j], args[j+1], args[j+2]
		res = append(res, KeyValuePair{Key: name, Value: value, NoDelim: delim == ""})
	}
	return res, nil
}

func parseEnv(req parseRequest) (*EnvCommand, error) {
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}
	envs, err := parseKvps(req.args, "ENV")
	if err != nil {
		return nil, err
	}
	return &EnvCommand{
		Env:             envs,
		withNameAndCode: newWithNameAndCode(req),
	}, nil
}

func parseMaintainer(req parseRequest) (*MaintainerCommand, error) {
	if len(req.args) != 1 {
		return nil, errExactlyOneArgument("MAINTAINER")
	}

	if err := req.flags.Parse(); err != nil {
		return nil, err
	}
	return &MaintainerCommand{
		Maintainer:      req.args[0],
		withNameAndCode: newWithNameAndCode(req),
	}, nil
}

func parseLabel(req parseRequest) (*LabelCommand, error) {
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	labels, err := parseKvps(req.args, "LABEL")
	if err != nil {
		return nil, err
	}

	return &LabelCommand{
		Labels:          labels,
		withNameAndCode: newWithNameAndCode(req),
	}, nil
}

func parseSourcesAndDest(req parseRequest, command string) (*SourcesAndDest, error) {
	srcs := req.args[:len(req.args)-1]
	dest := req.args[len(req.args)-1]
	if heredoc := parser.MustParseHeredoc(dest); heredoc != nil {
		return nil, errBadHeredoc(command, "a destination")
	}

	heredocLookup := make(map[string]parser.Heredoc)
	for _, heredoc := range req.heredocs {
		heredocLookup[heredoc.Name] = heredoc
	}

	var sourcePaths []string
	var sourceContents []SourceContent
	for _, src := range srcs {
		if heredoc := parser.MustParseHeredoc(src); heredoc != nil {
			content := heredocLookup[heredoc.Name].Content
			if heredoc.Chomp {
				content = parser.ChompHeredocContent(content)
			}
			sourceContents = append(sourceContents,
				SourceContent{
					Data:   content,
					Path:   heredoc.Name,
					Expand: heredoc.Expand,
				},
			)
		} else {
			sourcePaths = append(sourcePaths, src)
		}
	}

	return &SourcesAndDest{
		DestPath:       dest,
		SourcePaths:    sourcePaths,
		SourceContents: sourceContents,
	}, nil
}

func stringValuesFromFlagIfPossible(f *Flag) []string {
	if f == nil {
		return nil
	}

	return f.StringValues
}

func parseAdd(req parseRequest) (*AddCommand, error) {
	if len(req.args) < 2 {
		return nil, errNoDestinationArgument("ADD")
	}

	var flExcludes *Flag

	// silently ignore if not -labs
	if excludePatternsEnabled {
		flExcludes = req.flags.AddStrings("exclude")
	}

	flChown := req.flags.AddString("chown", "")
	flChmod := req.flags.AddString("chmod", "")
	flLink := req.flags.AddBool("link", false)
	flKeepGitDir := req.flags.AddBool("keep-git-dir", false)
	flChecksum := req.flags.AddString("checksum", "")
	flUnpack := req.flags.AddBool("unpack", false)
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	sourcesAndDest, err := parseSourcesAndDest(req, "ADD")
	if err != nil {
		return nil, err
	}

	var unpack *bool
	if _, ok := req.flags.used["unpack"]; ok {
		b := flUnpack.Value == "true"
		unpack = &b
	}

	return &AddCommand{
		withNameAndCode: newWithNameAndCode(req),
		SourcesAndDest:  *sourcesAndDest,
		Chown:           flChown.Value,
		Chmod:           flChmod.Value,
		Link:            flLink.Value == "true",
		KeepGitDir:      flKeepGitDir.Value == "true",
		Checksum:        flChecksum.Value,
		ExcludePatterns: stringValuesFromFlagIfPossible(flExcludes),
		Unpack:          unpack,
	}, nil
}

func parseCopy(req parseRequest) (*CopyCommand, error) {
	if len(req.args) < 2 {
		return nil, errNoDestinationArgument("COPY")
	}

	var flExcludes *Flag
	var flParents *Flag

	if excludePatternsEnabled {
		flExcludes = req.flags.AddStrings("exclude")
	}
	if parentsEnabled {
		flParents = req.flags.AddBool("parents", false)
	}

	flChown := req.flags.AddString("chown", "")
	flFrom := req.flags.AddString("from", "")
	flChmod := req.flags.AddString("chmod", "")
	flLink := req.flags.AddBool("link", false)

	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	sourcesAndDest, err := parseSourcesAndDest(req, "COPY")
	if err != nil {
		return nil, err
	}

	return &CopyCommand{
		withNameAndCode: newWithNameAndCode(req),
		SourcesAndDest:  *sourcesAndDest,
		From:            flFrom.Value,
		Chown:           flChown.Value,
		Chmod:           flChmod.Value,
		Link:            flLink.Value == "true",
		Parents:         flParents != nil && flParents.Value == "true",
		ExcludePatterns: stringValuesFromFlagIfPossible(flExcludes),
	}, nil
}

func parseFrom(req parseRequest) (*Stage, error) {
	stageName, err := parseBuildStageName(req.args)
	if err != nil {
		return nil, err
	}

	flPlatform := req.flags.AddString("platform", "")
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	code := strings.TrimSpace(req.original)
	return &Stage{
		BaseName:   req.args[0],
		OrigCmd:    req.command,
		StageName:  stageName,
		SourceCode: code,
		Commands:   []Command{},
		Platform:   flPlatform.Value,
		Loc:        req.location,
		Comment:    getComment(req.comments, stageName),
	}, nil
}

var validStageName = regexp.MustCompile("^[a-z][a-z0-9-_.]*$")

func parseBuildStageName(args []string) (stageName string, err error) {
	switch {
	case len(args) == 3 && strings.EqualFold(args[1], "as"):
		stageName = strings.ToLower(args[2])
		if !validStageName.MatchString(stageName) {
			return "", errors.Errorf("invalid name for build stage: %q, name can't start with a number or contain symbols", args[2])
		}
	case len(args) != 1:
		return "", errors.New("FROM requires either one or three arguments")
	}

	return stageName, nil
}

func parseOnBuild(req parseRequest) (*OnbuildCommand, error) {
	if len(req.args) == 0 {
		return nil, errAtLeastOneArgument("ONBUILD")
	}
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	triggerInstruction := strings.ToUpper(strings.TrimSpace(req.args[0]))
	switch strings.ToUpper(triggerInstruction) {
	case "ONBUILD":
		return nil, errors.New("Chaining ONBUILD via `ONBUILD ONBUILD` isn't allowed")
	case "MAINTAINER", "FROM":
		return nil, errors.Errorf("%s isn't allowed as an ONBUILD trigger", triggerInstruction)
	}

	original := regexp.MustCompile(`(?i)^\s*ONBUILD\s*`).ReplaceAllString(req.original, "")
	for _, heredoc := range req.heredocs {
		original += "\n" + heredoc.Content + heredoc.Name
	}

	return &OnbuildCommand{
		Expression:      original,
		withNameAndCode: newWithNameAndCode(req),
	}, nil
}

func parseWorkdir(req parseRequest) (*WorkdirCommand, error) {
	if len(req.args) != 1 {
		return nil, errExactlyOneArgument("WORKDIR")
	}

	err := req.flags.Parse()
	if err != nil {
		return nil, err
	}
	return &WorkdirCommand{
		Path:            req.args[0],
		withNameAndCode: newWithNameAndCode(req),
	}, nil
}

func parseShellDependentCommand(req parseRequest, emptyAsNil bool) (ShellDependantCmdLine, error) {
	var files []ShellInlineFile
	for _, heredoc := range req.heredocs {
		file := ShellInlineFile{
			Name:  heredoc.Name,
			Data:  heredoc.Content,
			Chomp: heredoc.Chomp,
		}
		files = append(files, file)
	}

	args := handleJSONArgs(req.args, req.attributes)
	if emptyAsNil && len(args) == 0 {
		args = nil
	}
	return ShellDependantCmdLine{
		CmdLine:      args,
		Files:        files,
		PrependShell: !req.attributes["json"],
	}, nil
}

func parseRun(req parseRequest) (*RunCommand, error) {
	cmd := &RunCommand{}

	for _, fn := range parseRunPreHooks {
		if err := fn(cmd, req); err != nil {
			return nil, err
		}
	}

	if err := req.flags.Parse(); err != nil {
		return nil, err
	}
	cmd.FlagsUsed = req.flags.Used()

	cmdline, err := parseShellDependentCommand(req, false)
	if err != nil {
		return nil, err
	}
	cmd.ShellDependantCmdLine = cmdline

	cmd.withNameAndCode = newWithNameAndCode(req)

	for _, fn := range parseRunPostHooks {
		if err := fn(cmd, req); err != nil {
			return nil, err
		}
	}

	return cmd, nil
}

func parseCmd(req parseRequest) (*CmdCommand, error) {
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	cmdline, err := parseShellDependentCommand(req, false)
	if err != nil {
		return nil, err
	}

	return &CmdCommand{
		ShellDependantCmdLine: cmdline,
		withNameAndCode:       newWithNameAndCode(req),
	}, nil
}

func parseEntrypoint(req parseRequest) (*EntrypointCommand, error) {
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	cmdline, err := parseShellDependentCommand(req, true)
	if err != nil {
		return nil, err
	}

	return &EntrypointCommand{
		ShellDependantCmdLine: cmdline,
		withNameAndCode:       newWithNameAndCode(req),
	}, nil
}

// parseOptInterval(flag) is the duration of flag.Value, or 0 if
// empty. An error is reported if the value is given and less than minimum duration.
func parseOptInterval(f *Flag) (time.Duration, error) {
	s := f.Value
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d == 0 {
		return 0, nil
	}

	const minimumDuration = time.Millisecond
	if d < minimumDuration {
		return 0, errors.Errorf("Interval %#v cannot be less than %s", f.name, minimumDuration)
	}
	return d, nil
}
func parseHealthcheck(req parseRequest) (*HealthCheckCommand, error) {
	if len(req.args) == 0 {
		return nil, errAtLeastOneArgument("HEALTHCHECK")
	}
	cmd := &HealthCheckCommand{
		withNameAndCode: newWithNameAndCode(req),
	}

	typ := strings.ToUpper(req.args[0])
	args := req.args[1:]
	if typ == "NONE" {
		if len(args) != 0 {
			return nil, errors.New("HEALTHCHECK NONE takes no arguments")
		}
		cmd.Health = &dockerspec.HealthcheckConfig{
			Test: []string{typ},
		}
	} else {
		healthcheck := dockerspec.HealthcheckConfig{}

		flInterval := req.flags.AddString("interval", "")
		flTimeout := req.flags.AddString("timeout", "")
		flStartPeriod := req.flags.AddString("start-period", "")
		flStartInterval := req.flags.AddString("start-interval", "")
		flRetries := req.flags.AddString("retries", "")

		if err := req.flags.Parse(); err != nil {
			return nil, err
		}

		switch typ {
		case "CMD":
			cmdSlice := handleJSONArgs(args, req.attributes)
			if len(cmdSlice) == 0 {
				return nil, errors.New("Missing command after HEALTHCHECK CMD")
			}

			if !req.attributes["json"] {
				typ = "CMD-SHELL"
			}

			healthcheck.Test = append([]string{typ}, cmdSlice...)
		default:
			return nil, errors.Errorf("Unknown type %#v in HEALTHCHECK (try CMD)", typ)
		}

		interval, err := parseOptInterval(flInterval)
		if err != nil {
			return nil, err
		}
		healthcheck.Interval = interval

		timeout, err := parseOptInterval(flTimeout)
		if err != nil {
			return nil, err
		}
		healthcheck.Timeout = timeout

		startPeriod, err := parseOptInterval(flStartPeriod)
		if err != nil {
			return nil, err
		}
		healthcheck.StartPeriod = startPeriod

		startInterval, err := parseOptInterval(flStartInterval)
		if err != nil {
			return nil, err
		}
		healthcheck.StartInterval = startInterval

		if flRetries.Value != "" {
			retries, err := strconv.ParseInt(flRetries.Value, 10, 32)
			if err != nil {
				return nil, err
			}
			if retries < 0 {
				return nil, errors.Errorf("--retries cannot be negative (%d)", retries)
			}
			healthcheck.Retries = int(retries)
		} else {
			healthcheck.Retries = 0
		}

		cmd.Health = &healthcheck
	}
	return cmd, nil
}

func parseExpose(req parseRequest) (*ExposeCommand, error) {
	portsTab := req.args

	if len(req.args) == 0 {
		return nil, errAtLeastOneArgument("EXPOSE")
	}

	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	slices.Sort(portsTab)
	return &ExposeCommand{
		Ports:           portsTab,
		withNameAndCode: newWithNameAndCode(req),
	}, nil
}

func parseUser(req parseRequest) (*UserCommand, error) {
	if len(req.args) != 1 {
		return nil, errExactlyOneArgument("USER")
	}

	if err := req.flags.Parse(); err != nil {
		return nil, err
	}
	return &UserCommand{
		User:            req.args[0],
		withNameAndCode: newWithNameAndCode(req),
	}, nil
}

func parseVolume(req parseRequest) (*VolumeCommand, error) {
	if len(req.args) == 0 {
		return nil, errAtLeastOneArgument("VOLUME")
	}

	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	cmd := &VolumeCommand{
		withNameAndCode: newWithNameAndCode(req),
	}

	for _, v := range req.args {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, errors.New("VOLUME specified can not be an empty string")
		}
		cmd.Volumes = append(cmd.Volumes, v)
	}
	return cmd, nil
}

func parseStopSignal(req parseRequest) (*StopSignalCommand, error) {
	if len(req.args) != 1 {
		return nil, errExactlyOneArgument("STOPSIGNAL")
	}
	sig := req.args[0]

	cmd := &StopSignalCommand{
		Signal:          sig,
		withNameAndCode: newWithNameAndCode(req),
	}
	return cmd, nil
}

func parseArg(req parseRequest) (*ArgCommand, error) {
	if len(req.args) < 1 {
		return nil, errAtLeastOneArgument("ARG")
	}

	flRequired := req.flags.AddBool("required", false)
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	required := flRequired.IsTrue()
	if _, ok := req.flags.used["required"]; ok {
		required = true
	}

	pairs := make([]KeyValuePairOptional, len(req.args))

	for i, arg := range req.args {
		kvpo := KeyValuePairOptional{}

		// 'arg' can just be a name or name-value pair. Note that this is different
		// from 'env' that handles the split of name and value at the parser level.
		// The reason for doing it differently for 'arg' is that we support just
		// defining an arg and not assign it a value (while 'env' always expects a
		// name-value pair). If possible, it will be good to harmonize the two.
		if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			if len(parts[0]) == 0 {
				return nil, errBlankCommandNames("ARG")
			}

			kvpo.Key = parts[0]
			kvpo.Value = &parts[1]
		} else {
			kvpo.Key = arg
		}
		kvpo.Comment = getComment(req.comments, kvpo.Key)
		pairs[i] = kvpo
	}

	return &ArgCommand{
		Args:            pairs,
		withNameAndCode: newWithNameAndCode(req),
		Required:        required,
	}, nil
}

func parseShell(req parseRequest) (*ShellCommand, error) {
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}
	shellSlice := handleJSONArgs(req.args, req.attributes)
	switch {
	case len(shellSlice) == 0:
		// SHELL []
		return nil, errAtLeastOneArgument("SHELL")
	case req.attributes["json"]:
		// SHELL ["powershell", "-command"]

		return &ShellCommand{
			Shell:           shellSlice,
			withNameAndCode: newWithNameAndCode(req),
		}, nil
	default:
		// SHELL powershell -command - not JSON
		return nil, errNotJSON("SHELL", req.original)
	}
}
