package parser

import "github.com/dexnore/dexfile/command"

func init() {
	// Dispatch Table. see line_parsers.go for the parse functions.
	// The command is parsed and mapped to the line parser. The line parser
	// receives the arguments but not the command, and returns an AST after
	// reformulating the arguments according to the rules in the parser
	// functions. Errors are propagated up by Parse() and the resulting AST can
	// be incorporated directly into the existing AST as a next.
	dispatch = map[string]func(string, *directives) (*Node, map[string]bool, error){
		command.ADD:         parseMaybeJSONToList,
		command.ARG:         parseNameOrNameVal,
		command.BUILD:       parseStringsWhitespaceDelimited,
		command.CMD:         parseMaybeJSON,
		command.COPY:        parseMaybeJSONToList,
		command.CTR:         parseStringsWhitespaceDelimited,
		command.ENTRYPOINT:  parseMaybeJSON,
		command.ENV:         parseEnv,
		command.EXEC:        parseMaybeJSON,
		command.EXPOSE:      parseStringsWhitespaceDelimited,
		command.FOR:         parseStringsWhitespaceDelimited,
		command.FROM:        parseStringsWhitespaceDelimited,
		command.FUNC:        parseStringsWhitespaceDelimited,
		command.HEALTHCHECK: parseHealthConfig,
		command.IF:          parseSubCommand,
		command.IMPORT:      parseStringsWhitespaceDelimited,
		command.LABEL:       parseLabel,
		command.MAINTAINER:  parseString,
		command.ONBUILD:     parseSubCommand,
		command.PROC:        parseMaybeJSON,
		command.RUN:         parseMaybeJSON,
		command.SHELL:       parseMaybeJSON,
		command.STOPSIGNAL:  parseString,
		command.USER:        parseString,
		command.VOLUME:      parseMaybeJSONToList,
		command.WORKDIR:     parseString,
	}
}
