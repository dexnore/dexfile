package parser

import (
	"regexp"

	"github.com/dexnore/dexfile/command"
)

var (
	dispatch      map[string]func(string, *directives) (*Node, map[string]bool, error)
	reWhitespace  = regexp.MustCompile(`[\t\v\f\r ]+`)
	reHeredoc     = regexp.MustCompile(`^(\d*)<<(-?)\s*([^<]*)$`)
	reLeadingTabs = regexp.MustCompile(`(?m)^\t+`)
)

// DefaultEscapeToken is the default escape token
const DefaultEscapeToken = '\\'

var (
	// Directives allowed to contain heredocs
	heredocDirectives = map[string]bool{
		command.ADD:  true,
		command.COPY: true,
		command.RUN:  true,
	}

	// Directives allowed to contain directives containing heredocs
	heredocCompoundDirectives = map[string]bool{
		command.ONBUILD: true,
	}
)
