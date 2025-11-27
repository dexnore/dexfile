package internal

import (
	"context"

	"github.com/moby/buildkit/client/llb"
)

func Stdout(st llb.State) string {
	stdout, _, _ := st.GetEnv(context.Background(), "STDOUT")
	return stdout
}

func Stderr(st llb.State) string {
	stdout, _, _ := st.GetEnv(context.Background(), "STDERR")
	return stdout
}
