package dex2llb

import (
	"context"
	"os"
	"path"
	"path/filepath"

	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/context/maincontext"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/system"
	"github.com/pkg/errors"
)

func detectRunMount(cmd *command, allDispatchStates *dispatchStates) bool {
	if c, ok := cmd.Command.(converter.WithExternalData); ok {
		mounts := converter.GetMounts(c)
		sources := make([]*dispatchState, len(mounts))
		for i, mount := range mounts {
			var from string
			if mount.From == "" {
				// this might not be accurate because the type might not have a real source (tmpfs for instance),
				// but since this is just for creating the sources map it should be ok (we don't want to check the value of
				// mount.Type because it might be a variable)
				from = dexfile.EmptyImageName
			} else {
				from = mount.From
			}
			stn, ok := allDispatchStates.findStateByName(from)
			if !ok {
				stn = &dispatchState{
					stage:        converter.Stage{BaseName: from},
					deps:         make(map[*dispatchState]converter.Command),
					paths:        make(map[string]struct{}),
					unregistered: true,
				}
			}
			sources[i] = stn
		}
		cmd.sources = sources
		return true
	}

	return false
}

func setCacheUIDGID(m *converter.Mount, st llb.State) llb.State {
	uid := 0
	gid := 0
	mode := os.FileMode(0755)
	if m.UID != nil {
		uid = int(*m.UID)
	}
	if m.GID != nil {
		gid = int(*m.GID)
	}
	if m.Mode != nil {
		mode = os.FileMode(*m.Mode)
	}
	return st.File(llb.Mkdir("/cache", mode, llb.WithUIDGID(uid, gid)), llb.WithCustomName("[internal] setting cache mount permissions"))
}

func dispatchRunMounts(d *dispatchState, c converter.ExecOp, sources []*dispatchState, opt dispatchOpt) (_ []llb.RunOption, err error) {
	var out []llb.RunOption
	mounts := converter.GetMounts(c)

	for i, mount := range mounts {
		if mount.From == "" && mount.Type == converter.MountTypeCache {
			mount.From = dexfile.EmptyImageName
		}
		if opt.mutableBuildContextOutput.Output == nil {
			ctxPaths := map[string]struct{}{}
			for p := range d.ctxPaths {
				ctxPaths[p] = struct{}{}
			}
			opts := filterPaths(ctxPaths)
			bctx := opt.convertOpt.MainContext
			if opt.convertOpt.BC != nil {
				bctx, err = opt.convertOpt.BC.MainContext(context.TODO(), opts...)
				if err != nil {
					return nil, err
				}
			} else if bctx == nil {
				bctx = maincontext.DefaultMainContext(opts...)
			}
			opt.mutableBuildContextOutput.Output = bctx.Output()
		}
		st := llb.NewState(opt.mutableBuildContextOutput)
		if mount.From != "" {
			src := sources[i]
			st = src.state
			if !src.dispatched {
				return nil, errors.Errorf("cannot mount from stage %q to %q, stage needs to be defined before current command", mount.From, mount.Target)
			}
		}
		var mountOpts []llb.MountOption
		if mount.Type == converter.MountTypeTmpfs {
			st = llb.Scratch()
			mountOpts = append(mountOpts, llb.Tmpfs(
				llb.TmpfsSize(mount.SizeLimit),
			))
		}
		if mount.Type == converter.MountTypeSecret {
			secret, err := dispatchSecret(d, mount, c.Location())
			if err != nil {
				return nil, err
			}
			out = append(out, secret)
			continue
		}
		if mount.Type == converter.MountTypeSSH {
			ssh, err := dispatchSSH(d, mount, c.Location())
			if err != nil {
				return nil, err
			}
			out = append(out, ssh)
			continue
		}
		if mount.ReadOnly {
			mountOpts = append(mountOpts, llb.Readonly)
		} else if mount.Type == converter.MountTypeBind && opt.llbCaps.Supports(pb.CapExecMountBindReadWriteNoOutput) == nil {
			mountOpts = append(mountOpts, llb.ForceNoOutput)
		}
		if mount.Type == converter.MountTypeCache {
			sharing := llb.CacheMountShared
			if mount.CacheSharing == converter.MountSharingPrivate {
				sharing = llb.CacheMountPrivate
			}
			if mount.CacheSharing == converter.MountSharingLocked {
				sharing = llb.CacheMountLocked
			}
			if mount.CacheID == "" {
				mount.CacheID = path.Clean(mount.Target)
			}
			mountOpts = append(mountOpts, llb.AsPersistentCacheDir(opt.cacheIDNamespace+"/"+mount.CacheID, sharing))
		}
		target := mount.Target
		if !system.IsAbsolutePath(filepath.Clean(mount.Target)) {
			dir, err := d.state.GetDir(context.TODO())
			if err != nil {
				return nil, err
			}
			target = filepath.Join("/", dir, mount.Target)
		}
		if target == "/" {
			return nil, errors.Errorf("invalid mount target %q", target)
		}
		if src := path.Join("/", mount.Source); src != "/" {
			mountOpts = append(mountOpts, llb.SourcePath(src))
		} else if mount.UID != nil || mount.GID != nil || mount.Mode != nil {
			st = setCacheUIDGID(mount, st)
			mountOpts = append(mountOpts, llb.SourcePath("/cache"))
		}

		out = append(out, llb.AddMount(target, st, mountOpts...))

		if mount.From == "" {
			d.ctxPaths[path.Join("/", filepath.ToSlash(mount.Source))] = struct{}{}
		} else {
			source := sources[i]
			source.paths[path.Join("/", filepath.ToSlash(mount.Source))] = struct{}{}
		}
	}
	return out, nil
}

func dispatchExecOpMount(d *dispatchState, index int, mount *converter.Mount, sources []*dispatchState, opt dispatchOpt) (st llb.State, err error) {
	if mount.From == "" && mount.Type == converter.MountTypeCache {
		mount.From = dexfile.EmptyImageName
	}
	if opt.mutableBuildContextOutput.Output == nil {
		ctxPaths := map[string]struct{}{}
		for p := range d.ctxPaths {
			ctxPaths[p] = struct{}{}
		}
		opts := filterPaths(ctxPaths)
		bctx := opt.convertOpt.MainContext
		if opt.convertOpt.BC != nil {
			bctx, err = opt.convertOpt.BC.MainContext(context.TODO(), opts...)
			if err != nil {
				return st, err
			}
		} else if bctx == nil {
			bctx = maincontext.DefaultMainContext(opts...)
		}
		opt.mutableBuildContextOutput.Output = bctx.Output()
	}
	st = llb.NewState(opt.mutableBuildContextOutput)
	if mount.From != "" {
		src := sources[index]
		st = src.state
		if !src.dispatched {
			return st, errors.Errorf("cannot mount from stage %q to %q, stage needs to be defined before current command", mount.From, mount.Target)
		}
	}
	if mount.Type == converter.MountTypeTmpfs {
		st = llb.Scratch()
	}
	if mount.Type == converter.MountTypeSecret {
		return
	}
	if mount.Type == converter.MountTypeSSH {
		return
	}
	if src := path.Join("/", mount.Source); src != "/" {
	} else if mount.UID != nil || mount.GID != nil || mount.Mode != nil {
		st = setCacheUIDGID(mount, st)
	}
	return
}
