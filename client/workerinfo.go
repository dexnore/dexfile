package client

import (
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

type WorkerInfo struct {
	client.WorkerInfo
}

func (w *WorkerInfo) ID() string {
	return w.WorkerInfo.ID
}

func (w *WorkerInfo) Label(key string) (string, bool) {
	v, ok := w.WorkerInfo.Labels[key]
	return v, ok
}

func (w *WorkerInfo) SupportsPlatform(platform ocispecs.Platform) bool {
	plat := pb.PlatformFromSpec(platform)
	for _, p := range w.WorkerInfo.Platforms {
		if pb.PlatformFromSpec(p).EqualVT(plat) {
			return true
		}
	}

	return false
}

func (w *WorkerInfo) Equal(worker WorkerInfo) bool {
	if w.ID() != worker.ID() {
		return false
	}
	for k, v := range worker.Labels {
		if value, ok := w.Label(k); ok {
			if v != value {
				return false
			}
		}
		return false
	}
	for _, p := range worker.Platforms {
		if !w.SupportsPlatform(p) {
			return false
		}
	}
	return true
}
