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
	"github.com/moby/buildkit/solver/pb"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

var (
	keyPaths        = "dexnore:dexfile::paths"
	keyContextPaths = "dexnore:dexfile::context-paths"
	keyImageConfig  = "dexnore:dexfile::image"
)

func dispatchExec(ctx context.Context, d *dispatchState, cmd converter.CommandExec, res *client.Result, opt dispatchOpt) (err error) {
	defer func () {
		if err != nil {
			err = parser.WithLocation(err, cmd.Location())
		}
	}()
	ds, dOpt := d.Clone(), opt.Clone()

	dc, err := toCommand(cmd, dOpt.allDispatchStates)
	if err != nil {
		return err
	}

	var execSources = dc.sources
	if err := dispatchRun(ds, cmd.RUN, dOpt.proxyEnv, dc.sources, dOpt); err != nil {
		return err
	}

	def, err := ds.state.Marshal(ctx)
	if err != nil {
		return err
	}

	var execop *execOp
	for i := len(def.Def) - 1; i >= 0; i-- {
		def := def.Def[i]
		var pop pb.Op
		if err := pop.UnmarshalVT(def); err != nil {
			return err
		}
		if execop = solveOp(&pop); execop != nil {
			break
		}
	}

	if execop == nil {
		return parser.WithLocation(errors.New("no conditional statement found"), cmd.Location())
	}

	ctr, ctrErr := createContainer(ctx, dOpt.solver.Client(), execop, res)
	if ctrErr != nil {
		return parser.WithLocation(ctrErr, cmd.Location())
	}

	if execop.Exec != nil && execop.Exec.CdiDevices != nil {
		return fmt.Errorf("CDI devices are not supported in [EXEC]")
	}

	var (
		stdout = bytes.NewBuffer(nil)
		stderr = bytes.NewBuffer(nil)
	)

	err = startProcess(ctx, ctr, cmd.TimeOut, *execop, func() error {
		// d.state = d.state.Async(func(ctx context.Context, _ llb.State, llbc *llb.Constraints) (llb.State, error) {
		p := platforms.DefaultSpec()
		if ds.platform != nil {
			p = *ds.platform
		}

		s, err := parseDefinationToState(ctx, stdout, dOpt.solver.Client(), p)
		if err != nil {
			return err
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
				return fmt.Errorf("unable to parse %s: %+v", keyPaths, vPaths)
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
				return fmt.Errorf("unable to parse %s: %+v", keyContextPaths, vCtxPaths)
			}
		}

		if vImgConfig != nil {
			var img dockerspec.DockerOCIImage
			if i, ok := vImgConfig.(string); ok {
				if err = json.Unmarshal([]byte(i), &img); err != nil {
					return err
				}
			} else if i, ok := vImgConfig.(fmt.Stringer); ok {
				if err = json.Unmarshal([]byte(i.String()), &img); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("unable to parse %s: %+v", keyImageConfig, vImgConfig)
			}

			d.image = internal.MergeDockerOCIImages(d.image, img)
		}

		d.state = llb.Merge([]llb.State{d.state, s})
		// return s, nil
		// })
		return nil
	}, &nopCloser{stdout}, &nopCloser{stderr})
	if err != nil {
		return parser.WithLocation(fmt.Errorf("%s\n%w", stderr.String(), err), cmd.Location())
	}
	return nil
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
