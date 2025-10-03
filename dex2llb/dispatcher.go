package dex2llb

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/docker/go-connections/nat"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/gitutil"
	"github.com/moby/buildkit/util/system"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/patternmatcher"
	"github.com/moby/sys/signal"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	mode "github.com/tonistiigi/dchapes-mode"
)

func dispatchEnv(d *dispatchState, c *converter.EnvCommand, lint *linter.Linter, _ ...llb.ConstraintsOpt) error {
	commitMessage := bytes.NewBufferString("ENV")
	for _, e := range c.Env {
		if e.NoDelim {
			msg := linter.RuleLegacyKeyValueFormat.Format(c.Name())
			lint.Run(&linter.RuleLegacyKeyValueFormat, c.Location(), msg)
		}
		validateNoSecretKey("ENV", e.Key, c.Location(), lint)
		commitMessage.WriteString(" " + e.String())
		d.state = d.state.AddEnv(e.Key, e.Value)
		d.image.Config.Env = addEnv(d.image.Config.Env, e.Key, e.Value)
	}
	return commitToHistory(&d.image, commitMessage.String(), false, nil, d.epoch)
}

func dispatchRun(d *dispatchState, c *converter.RunCommand, proxy *llb.ProxyEnv, sources []*dispatchState, dopt dispatchOpt, copts ...llb.ConstraintsOpt) error {
	var opt []llb.RunOption

	customname := c.String()

	if d.paths == nil {
		d.paths = make(map[string]struct{})
	}

	// Run command can potentially access any file. Mark the full filesystem as used.
	d.paths["/"] = struct{}{}

	var args = c.CmdLine
	if len(c.Files) > 0 {
		if len(args) != 1 || !c.PrependShell {
			return errors.Errorf("parsing produced an invalid run command: %v", args)
		}

		if heredoc := parser.MustParseHeredoc(args[0]); heredoc != nil {
			if d.image.OS != "windows" && strings.HasPrefix(c.Files[0].Data, "#!") {
				// This is a single heredoc with a shebang, so create a file
				// and run it.
				// NOTE: choosing to expand doesn't really make sense here, so
				// we silently ignore that option if it was provided.
				sourcePath := "/"
				destPath := "/dev/pipes/"

				f := c.Files[0].Name
				data := c.Files[0].Data
				if c.Files[0].Chomp {
					data = parser.ChompHeredocContent(data)
				}
				st := llb.Scratch().Dir(sourcePath).File(
					llb.Mkfile(f, 0755, []byte(data)),
					dexfile.WithInternalName("preparing inline document"),
					llb.Platform(*d.platform),
				)

				mount := llb.AddMount(destPath, st, llb.SourcePath(sourcePath), llb.Readonly)
				opt = append(opt, mount)

				args = []string{path.Join(destPath, f)}
			} else {
				// Just a simple heredoc, so just run the contents in the
				// shell: this creates the effect of a "fake"-heredoc, so that
				// the syntax can still be used for shells that don't support
				// heredocs directly.
				// NOTE: like above, we ignore the expand option.
				data := c.Files[0].Data
				if c.Files[0].Chomp {
					data = parser.ChompHeredocContent(data)
				}
				args = []string{data}
			}
			customname += fmt.Sprintf(" (%s)", summarizeHeredoc(c.Files[0].Data))
		} else {
			// More complex heredoc, so reconstitute it, and pass it to the
			// shell to handle.
			full := args[0]
			for _, file := range c.Files {
				full += "\n" + file.Data + file.Name
			}
			args = []string{full}
		}
	}
	if c.PrependShell {
		// Don't pass the linter function because we do not report a warning for
		// shell usage on run commands.
		args = withShell(d.image, args)
	}

	env, err := dispatchMetaExecOp(d, c, customname, args, proxy, sources, dopt, opt, copts...)
	if err != nil {
		return err
	}
	return commitToHistory(&d.image, "RUN "+runCommandString(args, d.buildArgs, env), true, &d.state, d.epoch)
}

func dispatchMetaExecOp(d *dispatchState, c converter.ExecOp, customname string, args []string, proxy *llb.ProxyEnv, sources []*dispatchState, dopt dispatchOpt, opt []llb.RunOption, copts ...llb.ConstraintsOpt) (shell.EnvGetter, error) {
	opt = append(opt, llb.Args(args), dfCmd(c), location(dopt.sourceMap, c.Location()))
	if d.ignoreCache {
		opt = append(opt, llb.IgnoreCache)
	}
	if proxy != nil {
		opt = append(opt, llb.WithProxy(*proxy))
	}

	runMounts, err := dispatchRunMounts(d, c, sources, dopt)
	if err != nil {
		return nil, err
	}
	opt = append(opt, runMounts...)

	securityOpt, err := dispatchRunSecurity(c)
	if err != nil {
		return nil, err
	}
	if securityOpt != nil {
		opt = append(opt, securityOpt)
	}

	networkOpt, err := dispatchRunNetwork(c)
	if err != nil {
		return nil, err
	}
	if networkOpt != nil {
		opt = append(opt, networkOpt)
	}

	if dopt.llbCaps != nil && dopt.llbCaps.Supports(pb.CapExecMetaUlimit) == nil {
		for _, u := range dopt.ulimit {
			opt = append(opt, llb.AddUlimit(llb.UlimitName(u.Name), u.Soft, u.Hard))
		}
	}

	if dopt.llbCaps != nil && dopt.llbCaps.Supports(pb.CapExecMetaCDI) == nil {
		for _, device := range dopt.devices {
			deviceOpts := []llb.CDIDeviceOption{
				llb.CDIDeviceName(device.Name),
			}
			if device.Optional {
				deviceOpts = append(deviceOpts, llb.CDIDeviceOptional)
			}
			opt = append(opt, llb.AddCDIDevice(deviceOpts...))
		}
		runDevices, err := dispatchRunDevices(c)
		if err != nil {
			return nil, err
		}
		opt = append(opt, runDevices...)
	}

	shlex := *dopt.shlex
	shlex.RawQuotes = true
	shlex.SkipUnsetEnv = true

	pl, err := d.state.GetPlatform(context.TODO(), copts...)
	if err != nil {
		return nil, err
	}
	env := mergeEnv(d.state, dopt.globalArgs)
	opt = append(opt, llb.WithCustomName(prefixCommand(d, uppercaseCmd(processCmdEnv(&shlex, customname, withSecretEnvMask(c, env))), d.prefixPlatform, pl, env)))
	for _, h := range dopt.extraHosts {
		opt = append(opt, llb.AddExtraHost(h.Host, h.IP))
	}

	if dopt.llbCaps != nil && dopt.llbCaps.Supports(pb.CapExecMountTmpfsSize) == nil {
		if dopt.shmSize > 0 {
			opt = append(opt, llb.AddMount("/dev/shm", llb.Scratch(), llb.Tmpfs(llb.TmpfsSize(dopt.shmSize))))
		}
	}

	if dopt.llbCaps != nil && dopt.llbCaps.Supports(pb.CapExecMetaCgroupParent) == nil {
		if len(dopt.cgroupParent) > 0 {
			opt = append(opt, llb.WithCgroupParent(dopt.cgroupParent))
		}
	}

	d.state = d.state.Run(opt...).Root()
	return env, nil
}

func dispatchWorkdir(d *dispatchState, c *converter.WorkdirCommand, commit bool, opt *dispatchOpt, copts ...llb.ConstraintsOpt) error {
	if commit {
		// This linter rule checks if workdir has been set to an absolute value locally
		// within the current dockerfile. Absolute paths in base images are ignored
		// because they might change and it is not advised to rely on them.
		//
		// We only run this check when commit is true. Commit is true when we are performing
		// this operation on a local call to workdir rather than one coming from
		// the base image. We only check the first instance of workdir being set
		// so successive relative paths are ignored because every instance is fixed
		// by fixing the first one.
		if !d.workdirSet && !system.IsAbs(c.Path, d.platform.OS) {
			msg := linter.RuleWorkdirRelativePath.Format(c.Path)
			opt.lint.Run(&linter.RuleWorkdirRelativePath, c.Location(), msg)
		}
		d.workdirSet = true
	}

	wd, err := system.NormalizeWorkdir(d.image.Config.WorkingDir, c.Path, d.platform.OS)
	if err != nil {
		return errors.Wrap(err, "normalizing workdir")
	}

	// NormalizeWorkdir returns paths with platform specific separators. For Windows
	// this will be of the form: \some\path, which is needed later when we pass it to
	// HCS.
	d.image.Config.WorkingDir = wd

	// From this point forward, we can use UNIX style paths.
	wd = system.ToSlash(wd, d.platform.OS)
	d.state = d.state.Dir(wd)

	if commit {
		withLayer := false
		if wd != "/" {
			mkdirOpt := []llb.MkdirOption{llb.WithParents(true)}
			if user := d.image.Config.User; user != "" {
				mkdirOpt = append(mkdirOpt, llb.WithUser(user))
			}
			if d.epoch != nil {
				mkdirOpt = append(mkdirOpt, llb.WithCreatedTime(*d.epoch))
			}
			platform := opt.targetPlatform
			if d.platform != nil {
				platform = *d.platform
			}
			env := mergeEnv(d.state, opt.globalArgs)
			d.state = d.state.File(llb.Mkdir(wd, 0755, mkdirOpt...),
				append(
					copts,
					llb.WithCustomName(prefixCommand(d, uppercaseCmd(processCmdEnv(opt.shlex, c.String(), env)), d.prefixPlatform, &platform, env)),
					location(opt.sourceMap, c.Location()),
					llb.Platform(*d.platform),
				)...,
			)
			withLayer = true
		}
		return commitToHistory(&d.image, "WORKDIR "+wd, withLayer, nil, d.epoch)
	}
	return nil
}

func dispatchCopy(d *dispatchState, cfg copyConfig, copts ...llb.ConstraintsOpt) error {
	dest, err := pathRelativeToWorkingDir(d.state, cfg.params.DestPath, *d.platform)
	if err != nil {
		return err
	}

	var copyOpt []llb.CopyOption

	if cfg.chown != "" {
		copyOpt = append(copyOpt, llb.WithUser(cfg.chown))
	}

	if len(cfg.excludePatterns) > 0 {
		// in theory we don't need to check whether there are any exclude patterns,
		// as an empty list is a no-op. However, performing the check makes
		// the code easier to understand and costs virtually nothing.
		copyOpt = append(copyOpt, llb.WithExcludePatterns(cfg.excludePatterns))
	}

	var chopt *llb.ChmodOpt
	if cfg.chmod != "" {
		chopt = &llb.ChmodOpt{}
		p, err := strconv.ParseUint(cfg.chmod, 8, 32)
		nonOctalErr := errors.Errorf("invalid chmod parameter: '%v'. it should be octal string and between 0 and 07777", cfg.chmod)
		if err == nil {
			if p > 0o7777 {
				return nonOctalErr
			}
			chopt.Mode = os.FileMode(p)
		} else {
			if _, err := mode.Parse(cfg.chmod); err != nil {
				var ne *strconv.NumError
				if errors.As(err, &ne) {
					return nonOctalErr // return nonOctalErr for compatibility if the value looks numeric
				}
				return err
			}
			chopt.ModeStr = cfg.chmod
		}
	}

	if cfg.checksum != "" {
		if !cfg.isAddCommand {
			return errors.New("checksum can't be specified for COPY")
		}
		if len(cfg.params.SourcePaths) != 1 {
			return errors.New("checksum can't be specified for multiple sources")
		}
		if !isHTTPSource(cfg.params.SourcePaths[0]) && !isGitSource(cfg.params.SourcePaths[0]) {
			return errors.New("checksum requires HTTP(S) or Git sources")
		}
	}

	commitMessage := bytes.NewBufferString("")
	if cfg.isAddCommand {
		commitMessage.WriteString("ADD")
	} else {
		commitMessage.WriteString("COPY")
	}

	if cfg.parents {
		commitMessage.WriteString(" " + "--parents")
	}
	if cfg.chown != "" {
		commitMessage.WriteString(" " + "--chown=" + cfg.chown)
	}
	if cfg.chmod != "" {
		commitMessage.WriteString(" " + "--chmod=" + cfg.chmod)
	}

	platform := cfg.opt.targetPlatform
	if d.platform != nil {
		platform = *d.platform
	}

	env := mergeEnv(d.state, d.opt.globalArgs)
	name := uppercaseCmd(processCmdEnv(cfg.opt.shlex, cfg.cmdToPrint.String(), env))
	pgName := prefixCommand(d, name, d.prefixPlatform, &platform, env)

	var a *llb.FileAction

	for _, src := range cfg.params.SourcePaths {
		commitMessage.WriteString(" " + src)
		gitRef, gitRefErr := gitutil.ParseGitRef(src)
		if gitRefErr == nil && !gitRef.IndistinguishableFromLocal {
			if !cfg.isAddCommand {
				return errors.New("source can't be a git ref for COPY")
			}
			// TODO: print a warning (not an error) if gitRef.UnencryptedTCP is true
			commit := gitRef.Commit
			if gitRef.SubDir != "" {
				commit += ":" + gitRef.SubDir
			}
			gitOptions := []llb.GitOption{llb.WithCustomName(pgName)}
			if cfg.keepGitDir {
				gitOptions = append(gitOptions, llb.KeepGitDir())
			}
			if cfg.checksum != "" {
				gitOptions = append(gitOptions, llb.GitChecksum(cfg.checksum))
			}
			st := llb.Git(gitRef.Remote, commit, gitOptions...)
			opts := append([]llb.CopyOption{&llb.CopyInfo{
				Mode:           chopt,
				CreateDestPath: true,
			}}, copyOpt...)
			if a == nil {
				a = llb.Copy(st, "/", dest, opts...)
			} else {
				a = a.Copy(st, "/", dest, opts...)
			}
		} else if isHTTPSource(src) {
			if !cfg.isAddCommand {
				return errors.New("source can't be a URL for COPY")
			}

			// Resources from remote URLs are not decompressed.
			// https://docs.docker.com/engine/reference/builder/#add
			//
			// Note: mixing up remote archives and local archives in a single ADD instruction
			// would result in undefined behavior: https://github.com/moby/buildkit/pull/387#discussion_r189494717
			u, err := url.Parse(src)
			f := "__unnamed__"
			if err == nil {
				if base := path.Base(u.Path); base != "." && base != "/" {
					f = base
				}
			}

			var checksum digest.Digest
			if cfg.checksum != "" {
				checksum, err = digest.Parse(cfg.checksum)
				if err != nil {
					return err
				}
			}

			st := llb.HTTP(src, llb.Filename(f), llb.WithCustomName(pgName), llb.Checksum(checksum), dfCmd(cfg.params))

			var unpack bool
			if cfg.unpack != nil {
				unpack = *cfg.unpack
			}

			opts := append([]llb.CopyOption{&llb.CopyInfo{
				Mode:           chopt,
				CreateDestPath: true,
				AttemptUnpack:  unpack,
			}}, copyOpt...)

			if a == nil {
				a = llb.Copy(st, f, dest, opts...)
			} else {
				a = a.Copy(st, f, dest, opts...)
			}
		} else {
			validateCopySourcePath(src, &cfg)
			var patterns []string
			if cfg.parents {
				// detect optional pivot point
				parent, pattern, ok := strings.Cut(src, "/./")
				if !ok {
					pattern = src
					src = "/"
				} else {
					src = parent
				}

				pattern, err = system.NormalizePath("/", pattern, d.platform.OS, false)
				if err != nil {
					return errors.Wrap(err, "removing drive letter")
				}

				patterns = []string{strings.TrimPrefix(pattern, "/")}
			}

			src, err = system.NormalizePath("/", src, d.platform.OS, false)
			if err != nil {
				return errors.Wrap(err, "removing drive letter")
			}

			unpack := cfg.isAddCommand
			if cfg.unpack != nil {
				unpack = *cfg.unpack
			}

			opts := append([]llb.CopyOption{&llb.CopyInfo{
				Mode:                chopt,
				FollowSymlinks:      true,
				CopyDirContentsOnly: true,
				IncludePatterns:     patterns,
				AttemptUnpack:       unpack,
				CreateDestPath:      true,
				AllowWildcard:       true,
				AllowEmptyWildcard:  true,
			}}, copyOpt...)

			if a == nil {
				a = llb.Copy(cfg.source, src, dest, opts...)
			} else {
				a = a.Copy(cfg.source, src, dest, opts...)
			}
		}
	}

	for _, src := range cfg.params.SourceContents {
		commitMessage.WriteString(" <<" + src.Path)

		data := src.Data
		f, err := system.CheckSystemDriveAndRemoveDriveLetter(src.Path, d.platform.OS, false)
		if err != nil {
			return errors.Wrap(err, "removing drive letter")
		}
		st := llb.Scratch().File(
			llb.Mkfile(f, 0644, []byte(data)),
			dexfile.WithInternalName("preparing inline document"),
			llb.Platform(*d.platform),
		)

		opts := append([]llb.CopyOption{&llb.CopyInfo{
			Mode:           chopt,
			CreateDestPath: true,
		}}, copyOpt...)

		if a == nil {
			a = llb.Copy(st, system.ToSlash(f, d.platform.OS), dest, opts...)
		} else {
			a = a.Copy(st, filepath.ToSlash(f), dest, opts...)
		}
	}

	commitMessage.WriteString(" " + cfg.params.DestPath)

	fileOpt := []llb.ConstraintsOpt{
		llb.WithCustomName(pgName),
		location(cfg.opt.sourceMap, cfg.location),
	}
	if d.ignoreCache {
		fileOpt = append(fileOpt, llb.IgnoreCache)
	}

	// cfg.opt.llbCaps can be nil in unit tests
	if cfg.opt.llbCaps != nil && cfg.opt.llbCaps.Supports(pb.CapMergeOp) == nil && cfg.link && cfg.chmod == "" {
		pgID := identity.NewID()
		d.cmdIndex-- // prefixCommand increases it
		pgName := prefixCommand(d, name, d.prefixPlatform, &platform, env)

		copyOpts := []llb.ConstraintsOpt{
			llb.Platform(*d.platform),
		}
		copyOpts = append(copyOpts, fileOpt...)
		copyOpts = append(copyOpts, llb.ProgressGroup(pgID, pgName, true))

		mergeOpts := slices.Clone(fileOpt)
		d.cmdIndex--
		mergeOpts = append(mergeOpts, llb.ProgressGroup(pgID, pgName, false), llb.WithCustomName(prefixCommand(d, "LINK "+name, d.prefixPlatform, &platform, env)))

		d.state = d.state.WithOutput(llb.Merge([]llb.State{d.state, llb.Scratch().File(a, append(copts, copyOpts...)...)}, append(copts, mergeOpts...)...).Output())
	} else {
		d.state = d.state.File(a, append(copts, fileOpt...)...)
	}

	return commitToHistory(&d.image, commitMessage.String(), true, &d.state, d.epoch)
}

type copyConfig struct {
	params          converter.SourcesAndDest
	excludePatterns []string
	source          llb.State
	isAddCommand    bool
	cmdToPrint      fmt.Stringer
	chown           string
	chmod           string
	link            bool
	keepGitDir      bool
	checksum        string
	parents         bool
	location        []parser.Range
	ignoreMatcher   *patternmatcher.PatternMatcher
	opt             dispatchOpt
	unpack          *bool
}

func dispatchMaintainer(d *dispatchState, c *converter.MaintainerCommand, _ ...llb.ConstraintsOpt) error {
	d.image.Author = c.Maintainer
	return commitToHistory(&d.image, fmt.Sprintf("MAINTAINER %v", c.Maintainer), false, nil, d.epoch)
}

func dispatchLabel(d *dispatchState, c *converter.LabelCommand, lint *linter.Linter, _ ...llb.ConstraintsOpt) error {
	commitMessage := bytes.NewBufferString("LABEL")
	if d.image.Config.Labels == nil {
		d.image.Config.Labels = make(map[string]string, len(c.Labels))
	}
	for _, v := range c.Labels {
		if v.NoDelim {
			msg := linter.RuleLegacyKeyValueFormat.Format(c.Name())
			lint.Run(&linter.RuleLegacyKeyValueFormat, c.Location(), msg)
		}
		d.image.Config.Labels[v.Key] = v.Value
		commitMessage.WriteString(" " + v.String())
	}
	return commitToHistory(&d.image, commitMessage.String(), false, nil, d.epoch)
}

func dispatchOnbuild(d *dispatchState, c *converter.OnbuildCommand, _ ...llb.ConstraintsOpt) error {
	d.image.Config.OnBuild = append(d.image.Config.OnBuild, c.Expression)
	return nil
}

func dispatchCmd(d *dispatchState, c *converter.CmdCommand, lint *linter.Linter, _ ...llb.ConstraintsOpt) error {
	validateUsedOnce(c, &d.cmd, lint)

	var args = c.CmdLine
	if c.PrependShell {
		if len(d.image.Config.Shell) == 0 {
			msg := linter.RuleJSONArgsRecommended.Format(c.Name())
			lint.Run(&linter.RuleJSONArgsRecommended, c.Location(), msg)
		}
		args = withShell(d.image, args)
	}
	d.image.Config.Cmd = args
	d.image.Config.ArgsEscaped = true //nolint:staticcheck // ignore SA1019: field is deprecated in OCI Image spec, but used for backward-compatibility with Docker image spec.
	return commitToHistory(&d.image, fmt.Sprintf("CMD %q", args), false, nil, d.epoch)
}

func dispatchEntrypoint(d *dispatchState, c *converter.EntrypointCommand, lint *linter.Linter, _ ...llb.ConstraintsOpt) error {
	validateUsedOnce(c, &d.entrypoint, lint)

	var args = c.CmdLine
	if c.PrependShell {
		if len(d.image.Config.Shell) == 0 {
			msg := linter.RuleJSONArgsRecommended.Format(c.Name())
			lint.Run(&linter.RuleJSONArgsRecommended, c.Location(), msg)
		}
		args = withShell(d.image, args)
	}
	d.image.Config.Entrypoint = args
	if !d.cmd.IsSet {
		d.image.Config.Cmd = nil
	}
	return commitToHistory(&d.image, fmt.Sprintf("ENTRYPOINT %q", args), false, nil, d.epoch)
}

func dispatchHealthcheck(d *dispatchState, c *converter.HealthCheckCommand, lint *linter.Linter, _ ...llb.ConstraintsOpt) error {
	validateUsedOnce(c, &d.healthcheck, lint)
	d.image.Config.Healthcheck = &dockerspec.HealthcheckConfig{
		Test:          c.Health.Test,
		Interval:      c.Health.Interval,
		Timeout:       c.Health.Timeout,
		StartPeriod:   c.Health.StartPeriod,
		StartInterval: c.Health.StartInterval,
		Retries:       c.Health.Retries,
	}
	return commitToHistory(&d.image, fmt.Sprintf("HEALTHCHECK %q", d.image.Config.Healthcheck), false, nil, d.epoch)
}

func dispatchExpose(d *dispatchState, c *converter.ExposeCommand, shlex *shell.Lex, opt dispatchOpt, _ ...llb.ConstraintsOpt) error {
	ports := []string{}
	env := mergeEnv(d.state, opt.globalArgs)
	for _, p := range c.Ports {
		ps, err := shlex.ProcessWords(p, env)
		if err != nil {
			return err
		}
		ports = append(ports, ps...)
	}
	c.Ports = ports

	ps, _, err := nat.ParsePortSpecs(c.Ports)
	if err != nil {
		return err
	}

	if d.image.Config.ExposedPorts == nil {
		d.image.Config.ExposedPorts = make(map[string]struct{})
	}
	for p := range ps {
		d.image.Config.ExposedPorts[string(p)] = struct{}{}
	}

	return commitToHistory(&d.image, fmt.Sprintf("EXPOSE %v", ps), false, nil, d.epoch)
}

func dispatchUser(d *dispatchState, c *converter.UserCommand, commit bool, _ ...llb.ConstraintsOpt) error {
	d.state = d.state.User(c.User)
	d.image.Config.User = c.User
	if commit {
		return commitToHistory(&d.image, fmt.Sprintf("USER %v", c.User), false, nil, d.epoch)
	}
	return nil
}

func dispatchVolume(d *dispatchState, c *converter.VolumeCommand, _ ...llb.ConstraintsOpt) error {
	if d.image.Config.Volumes == nil {
		d.image.Config.Volumes = map[string]struct{}{}
	}
	for _, v := range c.Volumes {
		if v == "" {
			return errors.New("VOLUME specified can not be an empty string")
		}
		d.image.Config.Volumes[v] = struct{}{}
	}
	return commitToHistory(&d.image, fmt.Sprintf("VOLUME %v", c.Volumes), false, nil, d.epoch)
}

func dispatchStopSignal(d *dispatchState, c *converter.StopSignalCommand, _ ...llb.ConstraintsOpt) error {
	if _, err := signal.ParseSignal(c.Signal); err != nil {
		return err
	}
	d.image.Config.StopSignal = c.Signal
	return commitToHistory(&d.image, fmt.Sprintf("STOPSIGNAL %v", c.Signal), false, nil, d.epoch)
}

func dispatchShell(d *dispatchState, c *converter.ShellCommand, _ ...llb.ConstraintsOpt) error {
	d.image.Config.Shell = c.Shell
	return commitToHistory(&d.image, fmt.Sprintf("SHELL %v", c.Shell), false, nil, d.epoch)
}

func dispatchArg(d *dispatchState, c *converter.ArgCommand, opt *dispatchOpt, _ ...llb.ConstraintsOpt) error {
	commitStrs := make([]string, 0, len(c.Args))
	usedBuildArgs := make(map[string]struct{}, len(opt.buildArgValues))
	for _, arg := range c.Args {
		validateNoSecretKey("ARG", arg.Key, c.Location(), opt.lint)
		_, hasValue := opt.buildArgValues[arg.Key]
		hasDefault := arg.Value != nil

		skipArgInfo := false // skip the arg info if the arg is inherited from global scope
		if !hasDefault && !hasValue {
			if v, ok := opt.globalArgs.Get(arg.Key); ok {
				arg.Value = &v
				skipArgInfo = true
				hasDefault = false
			}
		}

		if _, ok := usedBuildArgs[arg.Key]; !ok && hasValue {
			v := opt.buildArgValues[arg.Key]
			arg.Value = &v
			usedBuildArgs[arg.Key] = struct{}{}
			delete(opt.buildArgValues, arg.Key)
		} else if hasDefault {
			env := mergeEnv(d.state, opt.globalArgs)
			v, unmatched, err := opt.shlex.ProcessWord(*arg.Value, env)
			reportUnmatchedVariables(c, d.buildArgs, env, unmatched, opt)
			if err != nil {
				return err
			}
			arg.Value = &v
		}

		ai := argInfo{definition: arg, location: c.Location()}

		if arg.Value != nil {
			if _, ok := nonEnvArgs[arg.Key]; !ok {
				d.state = d.state.AddEnv(arg.Key, *arg.Value)
			}
			ai.value = *arg.Value
		} else if c.Required {
			return parser.WithLocation(errors.Errorf("missing required argument %q", arg.Key), c.Location())
		}

		if !skipArgInfo {
			d.outline.allArgs[arg.Key] = ai
		}
		d.outline.usedArgs[arg.Key] = struct{}{}

		d.buildArgs = append(d.buildArgs, arg)

		commitStr := arg.Key
		if arg.Value != nil {
			commitStr += "=" + *arg.Value
		}
		commitStrs = append(commitStrs, commitStr)
	}
	return commitToHistory(&d.image, "ARG "+strings.Join(commitStrs, " "), false, nil, d.epoch)
}
