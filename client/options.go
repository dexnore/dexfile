package client

import (
	"strings"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/client/config"
)

const localSessionIDPrefix = "local-sessionid:"

// source: https://github.com/moby/buildkit/blob/9fcedf9807077097847bda8d4db8b9c71d3110bf/frontend/dockerui/attr.go#L128-L136
func ParseLocalSessionIDs(opt map[string]string) map[string]string {
	m := map[string]string{}
	for k, v := range opt {
		if after, ok := strings.CutPrefix(k, localSessionIDPrefix); ok {
			m[after] = v
		}
	}
	return m
}

const keyNoCache = "no-cache"

func ParseIgnoreCache(opts map[string]string) (ignoreCache []string) {
	if v, ok := opts[keyNoCache]; ok {
		if v == "" {
			ignoreCache = []string{} // means all stages
		} else {
			ignoreCache = strings.Split(v, ",")
		}
	}

	return ignoreCache
}

var DefaultClientParseAttrs = []dexfile.ClientParseAttr{
	parser.ParseBuildPlatforms,
	parser.ParseTargetPlatforms,
	parser.ParseResolveMode,
	parser.ParseExtraHosts,
	parser.ParseShmSize,
	parser.ParseUlimits,
	parser.ParseNetMode,
	parser.ParseSourceDateEpoch,
	parser.ParseMultiPlatformRequested,
	parser.ParseCacheImports,
	parser.ParseAttests,
	parser.ParseBuildArgs,
	parser.ParseLabels,
	parser.ParseCacheMountNS,
	parser.ParseCgroupParent,
	parser.ParseTarget,
	parser.ParseHostname,
	parser.ParseLinterConfig,
}
