package shiftleft

import "github.com/moby/buildkit/frontend/gateway/client"

// ShiftLeftCheck defines a contract for a validation check.
type ShiftLeftCheck func(client.Client) error

// ShiftLeft encapsulates the client and its validation checks.
type shiftLeft struct {
	client client.Client
	checks []ShiftLeftCheck
}
