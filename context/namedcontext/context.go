package namedcontext

import (
	"strings"

	"github.com/containerd/platforms"
	"github.com/dexnore/dexfile"
	"github.com/dexnore/dexfile/context/namedcontext/internal"
	"github.com/distribution/reference"
	"github.com/pkg/errors"

	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

func NamedContext(name string, client dexfile.Client, opt dexfile.ContextOpt) (dexfile.NamedContext, error) {
	named, err := reference.ParseNormalizedNamed(name)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid context name %s", name)
	}
	name = strings.TrimSuffix(reference.FamiliarString(named), ":latest")

	var pp ocispecs.Platform
	if opt.Platform != nil {
		pp = *opt.Platform
	} else {
		pp = platforms.DefaultSpec()
	}
	pname := name + "::" + platforms.FormatAll(platforms.Normalize(pp))
	nc, err := internal.Named(name, pname, client, opt)
	if err != nil || nc != nil {
		return nc, err
	}
	nc, err = internal.Named(name, name, client, opt)
	if nc == nil {
		return nil, errors.Wrapf(err, "invalid context name %s", name)
	}
	return nc, err
}

func BaseContext(name string, client dexfile.Client, opt dexfile.ContextOpt) (dexfile.NamedContext, error) {
	named, err := reference.ParseNormalizedNamed(name)
	if err == nil {
		name = strings.TrimSuffix(reference.FamiliarString(named), ":latest")
	}

	var pp ocispecs.Platform
	if opt.Platform != nil {
		pp = *opt.Platform
	} else {
		pp = platforms.DefaultSpec()
	}
	pname := name + "::" + platforms.FormatAll(platforms.Normalize(pp))
	nc, err := internal.Base(name, pname, client, opt)
	if err != nil || nc != nil {
		return nc, err
	}
	nc, err = internal.Base(name, name, client, opt)
	if nc == nil {
		return nil, errors.Wrapf(err, "invalid context name [%s]", name)
	}
	return nc, err
}
