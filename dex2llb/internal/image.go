package internal

import (
	"maps"
	"slices"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

func MergeOCIPlatforms(p1, p2 ocispecs.Platform) ocispecs.Platform {
	if p2.OS != "" {
		return p2
	}

	return p1
}

func exclusiveSlice[S ~[]E, E any](s1, s2 S) S {
	if len(s2) > 0 {
		return s2
	}

	return s1
}

func exclusiveMap[S ~map[E]F, E comparable, F any](s1, s2 S) S {
	if len(s2) > 0 {
		return s2
	}

	return s1
}

func exclusiveString[S ~string](s1, s2 S) S {
	if s2 != "" {
		return s2
	}

	return s1
}

func MergeMap[S ~map[E]F, E comparable, F any](m1, m2 S) S {
	maps.Copy(m1, m2)

	return m1
}

func MergeOCIImageConfigs(cfg1, cfg2 ocispecs.ImageConfig) ocispecs.ImageConfig {
	return ocispecs.ImageConfig{
		User:         exclusiveString(cfg1.User, cfg2.User),
		ExposedPorts: exclusiveMap(cfg1.ExposedPorts, cfg2.ExposedPorts),
		Env:          slices.Concat(cfg1.Env, cfg2.Env),
		Entrypoint:   exclusiveSlice(cfg1.Entrypoint, cfg2.Entrypoint),
		Cmd:          exclusiveSlice(cfg1.Cmd, cfg2.Cmd),
		Volumes:      MergeMap(cfg1.Volumes, cfg2.Volumes),
		WorkingDir:   exclusiveString(cfg1.WorkingDir, cfg2.WorkingDir),
		Labels:       MergeMap(cfg1.Labels, cfg2.Labels),
		StopSignal:   exclusiveString(cfg1.StopSignal, cfg2.StopSignal),
		ArgsEscaped:  cfg1.ArgsEscaped || (len(cfg2.Entrypoint) > 0 || len(cfg2.Cmd) > 0) && cfg2.ArgsEscaped,
	}
}

func MergeOCIRootFS(rfs1, rfs2 ocispecs.RootFS) ocispecs.RootFS {
	return ocispecs.RootFS{
		Type:    exclusiveString(rfs1.Type, rfs2.Type),
		DiffIDs: slices.Concat(rfs1.DiffIDs, rfs2.DiffIDs),
	}
}

func MergeOCIImages(img1, img2 ocispecs.Image) ocispecs.Image {
	created := img1.Created
	if img2.Created != nil {
		created = img2.Created
	}

	return ocispecs.Image{
		Created:  created,
		Author:   exclusiveString(img1.Author, img2.Author),
		Platform: MergeOCIPlatforms(img1.Platform, img2.Platform),
		Config:   MergeOCIImageConfigs(img1.Config, img2.Config),
		RootFS:   MergeOCIRootFS(img1.RootFS, img2.RootFS),
		History:  slices.Concat(img1.History, img2.History),
	}
}

func MergeDockerOCIImageConfigExt(ext1, ext2 dockerspec.DockerOCIImageConfigExt) dockerspec.DockerOCIImageConfigExt {
	healthcheck := ext1.Healthcheck
	if ext2.Healthcheck != nil {
		healthcheck = ext2.Healthcheck
	}

	return dockerspec.DockerOCIImageConfigExt{
		Healthcheck: healthcheck,
		OnBuild:     slices.Concat(ext1.OnBuild, ext2.OnBuild),
		Shell:       exclusiveSlice(ext1.Shell, ext2.Shell),
	}
}

func MergeDockerOCIImageConfigs(cfg1, cfg2 dockerspec.DockerOCIImageConfig) dockerspec.DockerOCIImageConfig {
	return dockerspec.DockerOCIImageConfig{
		ImageConfig:             MergeOCIImageConfigs(cfg1.ImageConfig, cfg2.ImageConfig),
		DockerOCIImageConfigExt: MergeDockerOCIImageConfigExt(cfg1.DockerOCIImageConfigExt, cfg2.DockerOCIImageConfigExt),
	}
}

func MergeDockerOCIImages(img1, img2 dockerspec.DockerOCIImage) dockerspec.DockerOCIImage {
	return dockerspec.DockerOCIImage{
		Image:  MergeOCIImages(img1.Image, img2.Image),
		Config: MergeDockerOCIImageConfigs(img1.Config, img2.Config),
	}
}
