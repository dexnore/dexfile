package converter

import (
	"strings"

	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/pkg/errors"
)

type EndIf struct {
	withNameAndCode
}

func parseEndIf(req parseRequest) (*EndIf, error) {
	if len(req.args) > 0 {
		if s := strings.TrimSpace(strings.Join(req.args, " ")); s != "" {
			return nil, parser.WithLocation(errors.New("unexpected arguments to 'endif'"), req.location)
		}
	}

	return &EndIf{withNameAndCode: newWithNameAndCode(req)}, nil
}
