package checks

import (
	"fmt"
	"strings"

	"github.com/containerd/platforms"
	"github.com/moby/buildkit/frontend/gateway/client"
)

func BuildOptsWithPlatformsAndWorker(c client.Client) error {
	var bopts client.BuildOpts = c.BuildOpts()

	if err := hasWorkers(bopts.Workers); err != nil {
		return fmt.Errorf("invalid workers: %w", err)
	}

	platforms := strings.Split(bopts.Opts["build-platforms"], ",")
	return workerSupportsAllPlatforms(bopts, platforms)
}

func workerSupportsAllPlatforms(bopts client.BuildOpts, platform []string) error {
	ps := bopts.Workers[0].Platforms
	matcher := platforms.Any(ps...)
	for _, p := range platform {
		p, err := platforms.Parse(p)
		if err != nil {
			return fmt.Errorf("unsupported worker platform: invalid platform %q: %w", p, err)
		}
		if !matcher.Match(p) {
			return fmt.Errorf("platform %q not supported by worker %q", p, ps)
		}
	}
	return nil
}

func hasWorkers(workers []client.WorkerInfo) error {
	if len(workers) == 0 {
		return fmt.Errorf("no workers found. make sure buildkit supported container runtime is running")
	}
	return nil
}
