package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/containerd/platforms"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
)

func main() {
	ctx := context.Background()
	st := llb.Scratch()
	// otherSt := llb.Scratch()

	c, err := client.New(ctx, "unix:///Users/sai/.lima/buildkit/sock/buildkitd.sock")
	if err != nil {
		panic(err)
	}
	var helloworld = "hello world!"
	var someStr *string = &helloworld

	st = st.Async(func(ctx context.Context, s llb.State, llbc *llb.Constraints) (llb.State, error) {
		helloworld += " | in s.Async"
		s = s.Async(func(ctx context.Context, ss llb.State, c *llb.Constraints) (llb.State, error) {
			// helloworld += " | in s.Async.Async :)"
			return ss, nil
			// def, err := otherSt.Marshal(ctx)
			// if err != nil {
			// 	return s, err
			// }
			// return ss, fmt.Errorf("%s", bytes.Join(def.Def, bytes.NewBufferString("\n").Bytes()))
		})
		s = s.File(
			llb.Mkfile(
				"helloworld.txt",
				os.ModePerm,
				bytes.NewBufferString(*someStr).
					Bytes()),
		).
			AddEnv("somekey", "somevalue")
		def, err := s.Marshal(ctx, llb.Platform(platforms.DefaultSpec()))
		if err != nil {
			return s, err
		}

		res, err := c.Solve(ctx, def, client.SolveOpt{
			EnableSessionExporter: true,
			Internal:              true,
			Exports: []client.ExportEntry{
				{
					Type:      client.ExporterLocal,
					OutputDir: filepath.Join(".", "output"),
				},
			},
		}, nil)
		if err != nil {
			return s, err
		}

		fmt.Printf("solved in async successfully:\n\t%+v", res.ExporterResponse)
		return s, nil //fmt.Errorf("error in async: %+v", res.ExporterResponse)
	})
	helloworld = "outside st.Async"

	// st = st.Async(func(ctx context.Context, s llb.State, c *llb.Constraints) (llb.State, error) {
	// 	helloworld += " | in st.Async"
	// 	somevalue, ok, err := s.GetEnv(ctx, "somekey")
	// 	if !ok {
	// 		return s, fmt.Errorf("somevalue not found")
	// 	}
	// 	if err != nil {
	// 		return s, err
	// 	}

	// 	return s, fmt.Errorf("somevalue: %s", somevalue)
	// })
	// helloworld += " | outside st.Async"
	def, err := st.Marshal(ctx, llb.Platform(platforms.DefaultSpec()))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal: %q, def: %+v", err.Error(), def.Def))
	}
	helloworld += " | after Marshal"

	res, err := c.Solve(ctx, def, client.SolveOpt{
		EnableSessionExporter: true,
		Internal:              true,
	}, nil)
	if err != nil {
		panic(err)
	}
	helloworld += " | after Solve"

	fmt.Printf("\ndef: %s\n", bytes.Join(def.Def, bytes.NewBufferString("\n").Bytes()))
	fmt.Printf("solved successfully:\n\t%+v\n", res.ExporterResponse)
}

func loadDockerTar(r io.Reader) error {
	// no need to use moby/moby/client here
	cmd := exec.Command("docker", "load")
	cmd.Stdin = r
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
