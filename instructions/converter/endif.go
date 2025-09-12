package converter

import (
	"strings"
)

type EndIf struct {
	withNameAndCode
}

func parseEndIf(req parseRequest) (*EndIf, error) {
	if len(req.args) > 0 {
		if s := strings.TrimSpace(strings.Join(req.args, " ")); s != "" {
			return nil, &UnknownInstructionError{Instruction: s, Line: req.location[0].Start.Line}
		}
	}

	return &EndIf{withNameAndCode: newWithNameAndCode(req)}, nil
}
