package converter

import (
	"strings"
	"testing"

	"github.com/dexnore/dexfile/command"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/stretchr/testify/require"
)

func TestCommandsExactlyOneArgument(t *testing.T) {
	commands := []string{
		"MAINTAINER",
		"WORKDIR",
		"USER",
		"STOPSIGNAL",
	}

	for _, cmd := range commands {
		ast, err := parser.Parse(strings.NewReader(cmd))
		require.NoError(t, err)
		_, err = ParseInstruction(ast.AST.Children[0])
		require.EqualError(t, err, errExactlyOneArgument(cmd).Error())
	}
}

func TestCommandsAtLeastOneArgument(t *testing.T) {
	commands := []string{
		"ENV",
		"LABEL",
		"ONBUILD",
		"HEALTHCHECK",
		"EXPOSE",
		"VOLUME",
	}

	for _, cmd := range commands {
		ast, err := parser.Parse(strings.NewReader(cmd))
		require.NoError(t, err)
		_, err = ParseInstruction(ast.AST.Children[0])
		require.EqualError(t, err, errAtLeastOneArgument(cmd).Error())
	}
}

func TestCommandsNoDestinationArgument(t *testing.T) {
	commands := []string{
		"ADD",
		"COPY",
	}

	for _, cmd := range commands {
		ast, err := parser.Parse(strings.NewReader(cmd + " arg1"))
		require.NoError(t, err)
		_, err = ParseInstruction(ast.AST.Children[0])
		require.EqualError(t, err, errNoDestinationArgument(cmd).Error())
	}
}

func TestCommandsTooManyArguments(t *testing.T) {
	commands := []string{
		"ENV",
		"LABEL",
	}

	for _, cmd := range commands {
		node := &parser.Node{
			Original: cmd + "arg1 arg2 arg3",
			Value:    strings.ToLower(cmd),
			Next: &parser.Node{
				Value: "arg1",
				Next: &parser.Node{
					Value: "arg2",
					Next: &parser.Node{
						Value: "arg3",
						Next: &parser.Node{
							Value: "",
						},
					},
				},
			},
		}
		_, err := ParseInstruction(node)
		require.EqualError(t, err, errTooManyArguments(cmd).Error())
	}
}

func TestCommandsBlankNames(t *testing.T) {
	commands := []string{
		"ENV",
		"LABEL",
	}

	for _, cmd := range commands {
		node := &parser.Node{
			Original: cmd + " =arg2",
			Value:    strings.ToLower(cmd),
			Next: &parser.Node{
				Value: "",
				Next: &parser.Node{
					Value: "arg2",
					Next: &parser.Node{
						Value: "=",
					},
				},
			},
		}
		_, err := ParseInstruction(node)
		require.EqualError(t, err, errBlankCommandNames(cmd).Error())
	}
}

func TestHealthCheckCmd(t *testing.T) {
	node := &parser.Node{
		Value: command.HEALTHCHECK,
		Next: &parser.Node{
			Value: "CMD",
			Next: &parser.Node{
				Value: "hello",
				Next: &parser.Node{
					Value: "world",
				},
			},
		},
	}
	cmd, err := ParseInstruction(node)
	require.NoError(t, err)
	hc, ok := cmd.(*HealthCheckCommand)
	require.Equal(t, true, ok)
	expected := []string{"CMD-SHELL", "hello world"}
	require.Equal(t, expected, hc.Health.Test)
}

func TestParseOptInterval(t *testing.T) {
	flInterval := &Flag{
		name:     "interval",
		flagType: stringType,
		Value:    "50ns",
	}
	_, err := parseOptInterval(flInterval)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot be less than 1ms")

	flInterval.Value = "0ms"
	_, err = parseOptInterval(flInterval)
	require.NoError(t, err)

	flInterval.Value = "1ms"
	_, err = parseOptInterval(flInterval)
	require.NoError(t, err)
}

func TestNilLinter(t *testing.T) {
	for cmd := range command.Instructions {
		t.Run(cmd, func(t *testing.T) {
			t.Parallel()

			for _, tc := range []string{
				cmd + " foo=bar",
				cmd + " a",
				cmd + " a b",
				cmd + " a b c",
				cmd + " 0 0",
			} {
				t.Run(tc, func(t *testing.T) {
					ast, err := parser.Parse(strings.NewReader("FROM busybox\n" + tc))
					if err == nil {
						_, _, _ = Parse(ast.AST, nil)
					}
				})
			}
		})
	}
}

func TestNilLinterIfElse(t *testing.T) {
	t.Run("IfElse", func(t *testing.T) {
		ast, err := parser.Parse(strings.NewReader(`
# syntax=dexnore/dexfile:0

# This Dockerfile uses Dexfile syntax. For more information, see:
# https://github.com/dexnore/dexfile

ARG GO_ENTRYPOINT=.
ARG GO_OUTPUT_BIN_PATH=/dexfile-app
ARG LD_FLAGS
ARG BUILD_IMAGE \
    RUN_IMAGE
WORKDIR /home/dexfile/app
CTR --mount=target=. base-img
    IF PROC [ ! -f "go.mod" ]
        RUN echo "no 'go.mod' file found in the project" >&2 && exit 1;
    ENDIF
ENDCTR

FROM ${BUILD_IMAGE:-golang:latest} AS base
WORKDIR /home/dexfile/app

FROM base AS builder
COPY go.mod go.sum* /home/dexfile/app/
IF RUN [ ! -f "go.sum" ]
    RUN go mod tidy
ENDIF
RUN --mount=type=cache,target=/root/.cache,sharing=shared,id=dexfile-root-cache \
    --mount=type=cache,target=/go/pkg/mod,sharing=shared,id=dexfile-mod-cache \
    go mod download

ARG GO_ENTRYPOINT=$GO_ENTRYPOINT
ARG GO_OUTPUT_BIN_PATH=$GO_OUTPUT_BIN_PATH
ARG LD_FLAGS=$LD_FLAGS
RUN --mount=target=.,id=dexfile-app-src \
    --mount=type=cache,target=/root/.cache,sharing=shared,id=dexfile-root-cache \
    --mount=type=cache,target=/go/pkg/mod,sharing=shared,id=dexfile-mod-cache \
    set -euo pipefail && \
    echo "Trying build from GO_ENTRYPOINT=$GO_ENTRYPOINT" && \
    if CGO_ENABLED=0 go build \
        -ldflags="$LD_FLAGS" \
        -tags "osusergo netgo static_build" \
        -o "$GO_OUTPUT_BIN_PATH" \
        "$GO_ENTRYPOINT"; then \
        echo "Build succeeded from GO_ENTRYPOINT"; \
    else \
        echo "Build from GO_ENTRYPOINT failed, detecting main package dynamically..." >&2 && \
        MAIN_DIRS=$(find . -type f -name '*.go' \
            ! -name '*_test.go' \
            ! -path './vendor/*' \
            -exec grep -q '^package main' {} \; \
            -exec grep -q '^func main\s*(' {} \; \
            -print \
            | xargs -r -n1 dirname | sort -u) && \
        COUNT=$(echo "$MAIN_DIRS" | grep -c . || true) && \
        if [ "$COUNT" -eq 0 ]; then \
            echo "No main package found, build failed" >&2 && exit 1; \
        elif [ "$COUNT" -gt 1 ]; then \
            echo "Error: multiple main package directories found:" >&2 && \
            echo "$MAIN_DIRS" >&2 && \
            echo "Please set GO_ENTRYPOINT explicitly via build args." >&2 && \
            exit 1; \
        else \
            MAIN_DIR=$(echo "$MAIN_DIRS") && \
            echo "Detected main dir: $MAIN_DIR" && \
            CGO_ENABLED=0 go build \
                -ldflags="$LD_FLAGS" \
                -tags "osusergo netgo static_build" \
                -o "$GO_OUTPUT_BIN_PATH" \
                "$MAIN_DIR"; \
        fi; \
    fi


FROM ${RUN_IMAGE:-alpine:latest} AS prod
WORKDIR /home/dexfile/app
ARG GO_OUTPUT_BIN_PATH=$GO_OUTPUT_BIN_PATH
COPY --from=builder $GO_OUTPUT_BIN_PATH ./dexfile-app

FROM prod AS release
ENTRYPOINT [ "/home/dexfile/app/dexfile-app" ]
EXPOSE 3000
LABEL maintainer="@dexnore/dexfile"
LABEL moby.buildkit.frontend.network.none="true"
LABEL moby.buildkit.frontend.caps="moby.buildkit.frontend.inputs,moby.buildkit.frontend.subrequests,moby.buildkit.frontend.contexts"

FROM release
		`))
		if err == nil {
			stages, _, err := Parse(ast.AST, nil)
			require.NoError(t, err)
			require.Equal(t, len(stages), 8)
		}
		require.NoError(t, err)
	})
}

// func TestCommentsDetection(t *testing.T) {
// 	dt := `# foo sets foo
// ARG foo=bar

// # base defines first stage
// FROM busybox AS base
// # this is irrelevant
// ARG foo
// # bar defines bar
// # baz is something else
// ARG bar baz=123
// `

// 	ast, err := parser.Parse(bytes.NewBuffer([]byte(dt)))
// 	require.NoError(t, err)

// 	stages, meta, err := Parse(ast.AST, nil)
// 	require.NoError(t, err)

// 	require.Equal(t, "defines first stage", stages[0].Comment)
// 	require.Equal(t, "foo", meta[0].Args[0].Key)
// 	require.Equal(t, "sets foo", meta[0].Args[0].Comment)

// 	st := stages[0]

// 	require.Equal(t, "foo", st.Commands[0].(*ArgCommand).Args[0].Key)
// 	require.Equal(t, "", st.Commands[0].(*ArgCommand).Args[0].Comment)
// 	require.Equal(t, "bar", st.Commands[1].(*ArgCommand).Args[0].Key)
// 	require.Equal(t, "defines bar", st.Commands[1].(*ArgCommand).Args[0].Comment)
// 	require.Equal(t, "baz", st.Commands[1].(*ArgCommand).Args[1].Key)
// 	require.Equal(t, "is something else", st.Commands[1].(*ArgCommand).Args[1].Comment)
// }

func TestErrorCases(t *testing.T) {
	cases := []struct {
		name          string
		dockerfile    string
		expectedError string
	}{
		{
			name: "copyEmptyWhitespace",
			dockerfile: `COPY	
		quux \
      bar`,
			expectedError: "COPY requires at least two arguments",
		},
		{
			name:          "ONBUILD forbidden FROM",
			dockerfile:    "ONBUILD FROM scratch",
			expectedError: "FROM isn't allowed as an ONBUILD trigger",
		},
		{
			name:          "MAINTAINER unknown flag",
			dockerfile:    "MAINTAINER --boo joe@example.com",
			expectedError: "unknown flag: --boo",
		},
		{
			name:          "Chaining ONBUILD",
			dockerfile:    `ONBUILD ONBUILD RUN touch foobar`,
			expectedError: "Chaining ONBUILD via `ONBUILD ONBUILD` isn't allowed",
		},
		{
			name:          "Invalid instruction",
			dockerfile:    `FOO bar`,
			expectedError: "unknown instruction: FOO",
		},
		{
			name:          "Invalid instruction",
			dockerfile:    `foo bar`,
			expectedError: "unknown instruction: foo",
		},
	}
	for _, c := range cases {
		r := strings.NewReader(c.dockerfile)
		ast, err := parser.Parse(r)

		if err != nil {
			t.Fatalf("Error when parsing Dockerfile: %s", err)
		}
		n := ast.AST.Children[0]
		_, err = ParseInstruction(n)
		require.ErrorContains(t, err, c.expectedError)
	}
}

func TestRunCmdFlagsUsed(t *testing.T) {
	dockerfile := "RUN --mount=type=tmpfs,target=/foo/ echo hello"
	r := strings.NewReader(dockerfile)
	ast, err := parser.Parse(r)
	require.NoError(t, err)

	n := ast.AST.Children[0]
	c, err := ParseInstruction(n)
	require.NoError(t, err)
	require.IsType(t, &RunCommand{}, c)
	require.Equal(t, []string{"mount"}, c.(*RunCommand).FlagsUsed)
}

func BenchmarkParseBuildStageName(b *testing.B) {
	b.ReportAllocs()
	stageNames := []string{"STAGE_NAME", "StageName", "St4g3N4m3"}
	for i := 0; i < b.N; i++ {
		for _, s := range stageNames {
			_, _ = parseBuildStageName([]string{"foo", "as", s})
		}
	}
}
