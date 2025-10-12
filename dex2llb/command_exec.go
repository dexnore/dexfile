package dex2llb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/containerd/platforms"
	"github.com/dexnore/dexfile/dex2llb/internal"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

var (
	keyPaths        = "dexnore:dexfile::paths"
	keyContextPaths = "dexnore:dexfile::context-paths"
	keyImageConfig  = "dexnore:dexfile::image"
)

func dispatchExec(ctx context.Context, d *dispatchState, cmd converter.CommandExec, res *client.Result, opt dispatchOpt, copts ...llb.ConstraintsOpt) (err error) {
	defer func() {
		if err != nil {
			err = parser.WithLocation(err, cmd.Location())
		}
	}()
	ds := d.Clone()
	dOpt, err := opt.Clone()
	if err != nil {
		return err
	}

	dc, err := toCommand(cmd, dOpt.allDispatchStates)
	if err != nil {
		return err
	}

	var execSources = dc.sources
	ic, err := toCommand(cmd, dOpt.allDispatchStates)
	if err != nil {
		return err
	}
	if _, err := dispatch(ctx, ds, ic, dOpt, copts...); err != nil {
		return err
	}

	def, err := ds.state.Marshal(ctx, copts...)
	if err != nil {
		return err
	}

	execop, err := internal.MarshalToExecOp(def)
	if err != nil {
		return err
	}

	if execop == nil {
		return parser.WithLocation(errors.New("no conditional statement found"), cmd.Location())
	}

	ctrMounts, err := mountsForContainer(ctx, cmd.RUN, execop, ic.sources, res, ds, dOpt)
	if err != nil {
		return err
	}

	ctr, ctrErr := internal.CreateContainer(ctx, dOpt.solver.Client(), execop, ctrMounts)
	if ctrErr != nil {
		return parser.WithLocation(ctrErr, cmd.Location())
	}

	defer ctr.Release(ctx)

	if execop.Exec != nil && execop.Exec.CdiDevices != nil {
		return fmt.Errorf("CDI devices are not supported in [EXEC]")
	}

	var (
		stdout = bytes.NewBuffer(nil)
		stderr = bytes.NewBuffer(nil)
		retErr bool
	)

	retErr, _, err = internal.StartProcess(ctx, ctr, cmd.TimeOut, *execop, func() (bool, error) {
		p := platforms.DefaultSpec()
		if ds.platform != nil {
			p = *ds.platform
		}

		s, err := parseDefinationToState(ctx, stdout, dOpt.solver.Client(), p)
		if err != nil {
			return false, err
		}
		dc.sources = execSources

		d.image.History = append(d.image.History, ocispecs.History{
			CreatedBy:  "EXEC " + strings.Join(cmd.RUN.CmdLine, " "),
			Comment:    historyComment,
			EmptyLayer: false,
			Created:    d.epoch,
		})

		vPaths, _ := s.Value(ctx, keyPaths)
		vCtxPaths, _ := s.Value(ctx, keyContextPaths)
		vImgConfig, _ := s.Value(ctx, keyImageConfig)
		if vPaths != nil {
			if p, ok := vPaths.(string); ok {
				paths := strings.Split(p, "\n")
				for _, p := range paths {
					d.paths[p] = struct{}{}
				}
			} else if p, ok := vPaths.(fmt.Stringer); ok {
				paths := strings.Split(p.String(), "\n")
				for _, p := range paths {
					d.paths[p] = struct{}{}
				}
			} else {
				return false, fmt.Errorf("unable to parse %s: %+v", keyPaths, vPaths)
			}
		}

		if vCtxPaths != nil {
			if p, ok := vCtxPaths.(string); ok {
				paths := strings.Split(p, "\n")
				for _, p := range paths {
					d.ctxPaths[p] = struct{}{}
				}
			} else if p, ok := vCtxPaths.(fmt.Stringer); ok {
				paths := strings.Split(p.String(), "\n")
				for _, p := range paths {
					d.ctxPaths[p] = struct{}{}
				}
			} else {
				return false, fmt.Errorf("unable to parse %s: %+v", keyContextPaths, vCtxPaths)
			}
		}

		if vImgConfig != nil {
			var img dockerspec.DockerOCIImage
			if i, ok := vImgConfig.(string); ok {
				if err = json.Unmarshal([]byte(i), &img); err != nil {
					return false, err
				}
			} else if i, ok := vImgConfig.(fmt.Stringer); ok {
				if err = json.Unmarshal([]byte(i.String()), &img); err != nil {
					return false, err
				}
			} else {
				return false, fmt.Errorf("unable to parse %s: %+v", keyImageConfig, vImgConfig)
			}

			d.image = internal.MergeDockerOCIImages(d.image, img)
		}

		d.state = llb.Merge([]llb.State{d.state, s}, append(copts, llb.WithCustomNamef("EXEC %s", strings.Join(cmd.RUN.CmdLine, " ")))...)
		return false, nil
	}, internal.NopCloser(stdout), internal.NopCloser(stderr))
	if retErr {
		return parser.WithLocation(fmt.Errorf("%s\n%w", stderr.String(), err), cmd.Location())
	}
	return err
}

func parseDefinationToState(ctx context.Context, data io.Reader, c client.Client, platform ocispecs.Platform) (st llb.State, err error) {
	def, err := llb.ReadFrom(data)
	if err != nil {
		return st, err
	}

	if def == nil {
		return st, errors.Errorf("failed to resolve 'exec', empty definition")
	}

	res, err := c.Solve(ctx, client.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return st, err
	}

	ref, ok := res.FindRef(platforms.FormatAll(platform))
	if !ok {
		return st, errors.Errorf("failed to run 'exec' command: unable to tranform stdout to command")
	}

	return ref.ToState()
}
