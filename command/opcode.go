package command

const (
	ADD         = "add"
	ARG         = "arg"
	CMD         = "cmd"
	COPY        = "copy"
	ENTRYPOINT  = "entrypoint"
	ENV         = "env"
	EXPOSE      = "expose"
	FROM        = "from"
	HEALTHCHECK = "healthcheck"
	LABEL       = "label"
	MAINTAINER  = "maintainer"
	ONBUILD     = "onbuild"
	RUN         = "run"
	SHELL       = "shell"
	STOPSIGNAL  = "stopsignal"
	USER        = "user"
	VOLUME      = "volume"
	WORKDIR     = "workdir"

	// Dexfile specific
	ENDFOR  = "endfor"
	FOR     = "for"
	IF      = "if"
	ELSE    = "else"
	ENDIF   = "endif"
	WHILE   = "while"
	IMPORT  = "import"
	EXEC    = "exec"
	PROC    = "proc"
	FUNC    = "func"
	ENDFUNC = "endfunc"
	BUILD   = "build"
)

var Instructions = map[string]struct{}{
	ADD:         {},
	ARG:         {},
	CMD:         {},
	COPY:        {},
	ENTRYPOINT:  {},
	ENV:         {},
	EXPOSE:      {},
	FROM:        {},
	HEALTHCHECK: {},
	LABEL:       {},
	MAINTAINER:  {},
	ONBUILD:     {},
	RUN:         {},
	SHELL:       {},
	STOPSIGNAL:  {},
	USER:        {},
	VOLUME:      {},
	WORKDIR:     {},
	// Dexfile specific
	IMPORT:  {},
	IF:      {},
	ELSE:    {},
	ENDIF:   {},
	EXEC:    {},
	PROC:    {},
	FUNC:    {},
	ENDFUNC: {},
	FOR:     {},
	ENDFOR:  {},
	BUILD:   {},
}
