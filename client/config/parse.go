package parser

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/platforms"
	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/sbom"
	"github.com/distribution/reference"
	"github.com/docker/go-units"
	controlapi "github.com/moby/buildkit/api/services/control"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/attestations"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/tonistiigi/go-csvvalue"
)

func ParseBuildPlatforms(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	var defaultBuildPlatform ocispecs.Platform
	if len(bopts.Workers) > 0 && len(bopts.Workers[0].Platforms) > 0 {
		defaultBuildPlatform = bopts.Workers[0].Platforms[0]
	} else {
		defaultBuildPlatform = platforms.Normalize(platforms.DefaultSpec())
	}
	return func(config *dexfile.ClientConfig) error {
		config.BuildPlatforms = []ocispecs.Platform{defaultBuildPlatform}
		return nil
	}
}

func ParseTargetPlatforms(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		if v := bopts.Opts[keyTargetPlatform]; v != "" {
			config.TargetPlatforms, err = parsePlatforms(v)
		}
		return err
	}
}

// source: https://github.com/moby/buildkit/blob/9fcedf9807077097847bda8d4db8b9c71d3110bf/frontend/dockerui/attr.go#L18-L28
func parsePlatforms(v string) (pp []ocispecs.Platform, err error) {
	for _, v := range strings.Split(v, ",") {
		p, err := platforms.Parse(v)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse target platform %s", v)
		}
		pp = append(pp, platforms.Normalize(p))
	}
	return pp, nil
}

// source: https://github.com/moby/buildkit/blob/9fcedf9807077097847bda8d4db8b9c71d3110bf/frontend/dockerui/attr.go#L30-L41
func ParseResolveMode(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) error {
		switch v := bopts.Opts[keyImageResolveMode]; v {
		case pb.AttrImageResolveModeDefault, "":
			config.ImageResolveMode = llb.ResolveModeDefault
		case pb.AttrImageResolveModeForcePull:
			config.ImageResolveMode = llb.ResolveModeForcePull
		case pb.AttrImageResolveModePreferLocal:
			config.ImageResolveMode = llb.ResolveModePreferLocal
		default:
			return errors.Errorf("invalid image-resolve-mode: %s", v)
		}
		return nil
	}
}

// source: https://github.com/moby/buildkit/blob/9fcedf9807077097847bda8d4db8b9c71d3110bf/frontend/dockerui/attr.go#L43-L64
func ParseExtraHosts(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		config.ExtraHosts, err = extraHosts(bopts.Opts[keyGlobalAddHosts])
		return err
	}
}

func extraHosts(v string) (extraHosts []llb.HostIP, err error) {
	err = parseCSVValues(v, func(field string) error {
		key, val, ok := strings.Cut(strings.ToLower(field), "=")
		if !ok {
			return errors.Errorf("invalid key-value pair %s", field)
		}
		ip := net.ParseIP(val)
		if ip == nil {
			return errors.Errorf("failed to parse IP %s", val)
		}
		extraHosts = append(extraHosts, llb.HostIP{Host: key, IP: ip})
		return nil
	})

	return extraHosts, err
}

func parseCSVValues(v string, parser func(field string) error) error {
	if v == "" {
		return nil
	}
	fields, err := csvvalue.Fields(v, nil)
	if err != nil {
		return err
	}

	for _, field := range fields {
		if err := parser(field); err != nil {
			return err
		}
	}

	return nil
}

func ParseShmSize(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	v := bopts.Opts[keyShmSize]
	return func(config *dexfile.ClientConfig) (err error) {
		if len(v) == 0 {
			// config.ShmSize = 0
			return nil
		}
		config.ShmSize, err = strconv.ParseInt(v, 10, 64)
		return err
	}
}

// source: https://github.com/moby/buildkit/blob/9fcedf9807077097847bda8d4db8b9c71d3110bf/frontend/dockerui/attr.go#L77-L98
func ParseUlimits(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		config.Ulimits, err = ulimits(bopts.Opts[keyUlimit])
		return err
	}
}

func ulimits(v string) (ulimits []*pb.Ulimit, err error) {
	err = parseCSVValues(v, func(field string) error {
		ulimit, err := units.ParseUlimit(field)
		if err != nil {
			return err
		}
		ulimits = append(ulimits, &pb.Ulimit{
			Name: ulimit.Name,
			Soft: ulimit.Soft,
			Hard: ulimit.Hard,
		})
		return nil
	})

	return ulimits, err
}

// source: https://github.com/moby/buildkit/blob/9fcedf9807077097847bda8d4db8b9c71d3110bf/frontend/dockerui/attr.go#L100-L114
func ParseNetMode(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		switch v := bopts.Opts[keyForceNetwork]; v {
		case "none":
			config.NetworkMode = llb.NetModeNone
		case "host":
			config.NetworkMode = llb.NetModeHost
		case "sandbox", "":
			config.NetworkMode = llb.NetModeSandbox
		default:
			return errors.Errorf("invalid netmode %s", v)
		}
		return nil
	}
}

// source: https://github.com/moby/buildkit/blob/9fcedf9807077097847bda8d4db8b9c71d3110bf/frontend/dockerui/attr.go#L116-L126
func ParseSourceDateEpoch(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	v := bopts.Opts[keySourceDateEpoch]
	return func(c *dexfile.ClientConfig) error {
		if v == "" {
			return nil
		}
		sde, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return errors.Wrapf(err, "invalid SOURCE_DATE_EPOCH: %s", v)
		}
		tm := time.Unix(sde, 0).UTC()
		c.Epoch = &tm
		return nil
	}
}

// source: https://github.com/moby/buildkit/blob/9fcedf9807077097847bda8d4db8b9c71d3110bf/frontend/dockerui/attr.go#L138-L146
func filter(opt map[string]string, key string) map[string]string {
	m := map[string]string{}
	for k, v := range opt {
		if after, ok := strings.CutPrefix(k, key); ok {
			m[after] = v
		}
	}
	return m
}

func ParseMultiPlatformRequested(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		multiPlatform := len(config.TargetPlatforms) > 1
		if v := bopts.Opts[keyMultiPlatformArg]; v != "" {
			bopts.Opts[keyMultiPlatform] = v
		}
		if v := bopts.Opts[keyMultiPlatformArg]; v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return errors.Errorf("invalid boolean value for multi-platform: %s", v)
			}
			if !b && multiPlatform {
				return errors.Errorf("conflicting config: returning multiple target platforms is not allowed")
			}
			multiPlatform = b
		}

		config.MultiPlatformRequested = multiPlatform
		return nil
	}
}

func ParseCacheImports(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	var cacheImports []client.CacheOptionsEntry
	return func(config *dexfile.ClientConfig) (err error) {
		cacheImportsStr := bopts.Opts[keyCacheImports]
		if cacheImportsStr != "" {
			var cacheImportsUM []*controlapi.CacheOptionsEntry
			if err := json.Unmarshal([]byte(cacheImportsStr), &cacheImportsUM); err != nil {
				return errors.Wrapf(err, "failed to unmarshal %s (%q)", keyCacheImports, cacheImportsStr)
			}
			for _, um := range cacheImportsUM {
				cacheImports = append(cacheImports, client.CacheOptionsEntry{Type: um.Type, Attrs: um.Attrs})
			}
		}

		config.CacheImports = cacheImports
		return nil
	}
}

// source: https://github.com/moby/buildkit/blob/cc0cb089361067b42c639fd85ba44e42fbba15d0/frontend/dockerui/config.go#L258-L284
func ParseAttests(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	attests, err := attestations.Parse(bopts.Opts)
	return func(config *dexfile.ClientConfig) error {
		if err != nil {
			return err
		}
		if attrs, ok := attests[attestations.KeyTypeSbom]; ok {
			params := make(map[string]string)
			var ref reference.Named
			for k, v := range attrs {
				if k == "generator" {
					ref, err = reference.ParseNormalizedNamed(v)
					if err != nil {
						return errors.Wrapf(err, "failed to parse sbom scanner %s", v)
					}
					ref = reference.TagNameOnly(ref)
				} else {
					params[k] = v
				}
			}
			if ref == nil {
				return errors.Errorf("sbom scanner cannot be empty")
			}

			config.SBOM = &sbom.SBOM{
				Generator:  ref.String(),
				Parameters: params,
			}

			return nil
		}

		return err
	}
}

func ParseBuildArgs(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		config.BuildArgs = filter(bopts.Opts, buildArgPrefix)
		return nil
	}
}

func ParseLabels(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		config.Labels = filter(bopts.Opts, labelPrefix)
		return nil
	}
}

func ParseCacheMountNS(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		config.CacheIDNamespace = bopts.Opts[keyCacheNSArg]
		return nil
	}
}

func ParseCgroupParent(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		config.CgroupParent = bopts.Opts[keyCgroupParent]
		return nil
	}
}

func ParseTarget(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		config.Target = bopts.Opts[KeyTarget]
		return nil
	}
}

func ParseHostname(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		if v, ok := bopts.Opts[keyHostnameArg]; ok && len(v) > 0 {
			bopts.Opts[keyHostname] = v
		}
		config.Hostname = bopts.Opts[keyHostname]
		return nil
	}
}

func ParseLinterConfig(bopts client.BuildOpts) dexfile.ClientConfigOpt {
	return func(config *dexfile.ClientConfig) (err error) {
		if v, ok := bopts.Opts[keyFrontendLintArg]; ok {
			config.LinterConfig, err = linter.ParseLintOptions(v)
			if err != nil {
				return errors.Wrapf(err, "failed to parse %s", keyFrontendLintArg)
			}
		}
		return nil
	}
}
