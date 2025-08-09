//go:build !windows

package converter

import "github.com/pkg/errors"

func errNotJSON(command, _ string) error {
	return errors.Errorf("%s requires the arguments to be in JSON form", command)
}
