package shiftleft

import (
	"github.com/dexnore/dexfile/shiftleft/checks"
	"github.com/moby/buildkit/frontend/gateway/client"
)

// NewShiftLeft constructs a new ShiftLeft instance with the provided client.
func NewShiftLeft(c client.Client) *shiftLeft {
	return &shiftLeft{
		client: c,
		checks: []ShiftLeftCheck{},
	}
}

// Register adds one or more checks to the ShiftLeft instance.
func (s *shiftLeft) Register(checks ...ShiftLeftCheck) {
	s.checks = append(s.checks, checks...)
}

// Validate runs all registered checks and returns the first error encountered.
func (s *shiftLeft) Validate() error {
	for _, check := range s.checks {
		if err := check(s.client); err != nil {
			return err
		}
	}
	return nil
}

// RegisterDefaultChecks adds the default checks to the ShiftLeft instance.
func (s *shiftLeft) RegisterDefaultChecks() {
	s.Register(
		checks.BuildOptsWithPlatformsAndWorker,
		// checks.VerifyCanCache,
		// checks.VerifyCanExportResult,
	)
}
