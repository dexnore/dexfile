package client

import (
	"maps"
	"slices"

	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/apicaps"
	"github.com/pkg/errors"
)

func (bo *BuildOpts) SetOpt(key, value string) error {
	_, ok := bo.BuildOpts.Opts[key]
	bo.BuildOpts.Opts[key] = value
	if !ok {
		return nil
	}
	return errors.Errorf("BuildOpts with key %s exists", key)
}

func (bo *BuildOpts) DelOpt(key string) error {
	_, ok := bo.BuildOpts.Opts[key]
	delete(bo.BuildOpts.Opts, key)
	if !ok {
		return errors.Errorf("BuildOpts with key %s exists", key)
	}
	return nil
}

func (bo *BuildOpts) WithSession(id string) {
	bo.BuildOpts.SessionID = id
}

func (bo *BuildOpts) AsProduct(name string) {
	bo.BuildOpts.Product = name
}

func (bo *BuildOpts) Caps() apicaps.CapSet {
	return bo.BuildOpts.Caps
}

func (bo *BuildOpts) LLBCaps() apicaps.CapSet {
	return bo.BuildOpts.LLBCaps
}

// AddOrReplaceWorker implements client.BuildOpts.
func (bo *BuildOpts) AddOrReplaceWorker(w WorkerInfo) bool {
	for _, wi := range bo.Workers {
		wi := WorkerInfo{WorkerInfo: wi}
		if wi.Equal(w) {
			bo.Workers = append(bo.Workers, w.WorkerInfo)
			return true
		}
	}
	bo.Workers = append(bo.Workers, w.WorkerInfo)
	return false
}

// RemoveWorker implements client.BuildOpts.
func (bo *BuildOpts) RemoveWorker(id string) (wi WorkerInfo, _ error) {
	bo.Workers = slices.DeleteFunc(bo.Workers, func(w client.WorkerInfo) bool {
		wi = WorkerInfo{WorkerInfo: w}
		return w.ID == id
	})
	return wi, nil
}

// Worker implements client.BuildOpts.
func (bo *BuildOpts) Worker(id string) (wi WorkerInfo, ok bool) {
	return wi, slices.ContainsFunc(bo.Workers, func(w client.WorkerInfo) bool {
		if w.ID == id {
			wi = WorkerInfo{WorkerInfo: w}
			return true
		}
		return false
	})
}

func (bo *BuildOpts) ListWorkers() []WorkerInfo {
	workers := make([]WorkerInfo, len(bo.Workers))
	for i, w := range bo.Workers {
		workers[i] = WorkerInfo{WorkerInfo: w}
	}
	return workers
}

func (bo BuildOpts) Clone() BuildOpts {
	return BuildOpts{
		BuildOpts: client.BuildOpts{
			Opts:      maps.Clone(bo.Opts),
			SessionID: bo.SessionID,
			Workers:   slices.Clone(bo.Workers),
			Product:   bo.Product,
			LLBCaps:   bo.LLBCaps(),
			Caps:      bo.Caps(),
		},
	}
}

func (bo *Client) AddOrReplaceWorker(w WorkerInfo) bool {
	return bo.buildOpts.AddOrReplaceWorker(w)
}
func (bo *Client) AsProduct(name string) {
	bo.buildOpts.AsProduct(name)
}
func (bo *Client) Caps() apicaps.CapSet {
	return bo.buildOpts.Caps()
}
func (bo *Client) LLBCaps() apicaps.CapSet {
	return bo.buildOpts.LLBCaps()
}
func (bo *Client) ListWorkers() []WorkerInfo {
	return bo.buildOpts.ListWorkers()
}
func (bo *Client) RemoveWorker(id string) (wi WorkerInfo, _ error) {
	return bo.buildOpts.RemoveWorker(id)
}
func (bo *Client) SetOpt(key string, value string) error {
	return bo.buildOpts.SetOpt(key, value)
}
func (bo *Client) DelOpt(key string) error {
	return bo.buildOpts.DelOpt(key)
}
func (bo *Client) WithSession(id string) {
	bo.buildOpts.WithSession(id)
}
func (bo *Client) Worker(id string) (wi WorkerInfo, ok bool) {
	return bo.buildOpts.Worker(id)
}
