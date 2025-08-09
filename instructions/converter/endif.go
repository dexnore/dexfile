package converter

import (
	"regexp"
)

type EndIf struct {
	withNameAndCode
}

func parseEndIf(req parseRequest) (*EndIf, error) {
	if len(req.args) > 0 {
		original := regexp.MustCompile(`(?i)^\s*ENDIF\s*`).ReplaceAllString(req.original, "")
		for _, heredoc := range req.heredocs {
			original += "\n" + heredoc.Content + heredoc.Name
		}
		if len(original) > 0 {
			return nil, &UnknownInstructionError{Instruction: original, Line: req.location[0].Start.Line}
		}
	}
	endIf := &EndIf{}
	endIf.withNameAndCode = newWithNameAndCode(req)

	return endIf, nil
}
