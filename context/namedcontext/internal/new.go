package internal

import (
	"github.com/dexnore/dexfile"
)

func Named(name string, nameWithPlatform string, bc dexfile.Client, opt dexfile.ContextOpt) (*NamedContext, error) {
	opts := bc.BuildOpts().Opts
	contextKey := contextPrefix + nameWithPlatform
	v, ok := opts[contextKey]
	if !ok {
		return nil, nil
	}

	return &NamedContext{
		input:            v,
		client:           bc,
		name:             name,
		nameWithPlatform: nameWithPlatform,
		opt:              opt,
	}, nil
}

func Base(name string, nameWithPlatform string, bc dexfile.Client, opt dexfile.ContextOpt) (*NamedContext, error) {
	return &NamedContext{
		input:            name,
		client:           bc,
		name:             name,
		nameWithPlatform: nameWithPlatform,
		opt:              opt,
	}, nil
}
