package main

import (
	"context"

	"github.com/dexnore/dexfile/builder"
	"github.com/moby/buildkit/frontend/gateway/grpcclient"
)

func main() {
	err := grpcclient.RunFromEnvironment(context.Background(), builder.Build)
	if err != nil {
		panic(err)
	}
}
