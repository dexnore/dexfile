package shiftleft

import (
	"github.com/moby/buildkit/frontend/gateway/client"
)

func Error(c client.Client) error {
	shiftleft := NewShiftLeft(c)
	shiftleft.RegisterDefaultChecks()
	return shiftleft.Validate()
}
