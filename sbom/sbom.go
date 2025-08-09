package sbom

import (
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/attestations/sbom"
)

type SBOM struct {
	Generator  string
	Parameters map[string]string
}

type SBOMTargets struct {
	Core   llb.State
	Extras map[string]llb.State

	IgnoreCache bool
}

type Scanner = sbom.Scanner

var CreateSBOMScanner = sbom.CreateSBOMScanner
