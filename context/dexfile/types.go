package dexfile

import (
	"github.com/dexnore/dexfile"
)

type df struct {
	client dexfile.Client
	bc     dexfile.BuildContext
}

func New(client dexfile.Client, bc dexfile.BuildContext) *df {
	return &df{
		client: client,
		bc:     bc,
	}
}
