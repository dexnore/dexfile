package converter

import (
	"fmt"
	"strings"

	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/pkg/errors"
)

type ImportCommand struct {
	StageName string    // name of the stage
	Commands  []Command // commands contained within the stage
	OrigCmd   string    // original IMPORT command, used for rule checks
	BaseName  string    // name of the base stage or source

	Context  string // context of the base stage
	Target   string // target platform
	FileName string // target filename
	Platform string // platform of base source to use

	Comment string // doc-comment directly above the stage

	SourceCode string         // contents of the defining IMPORT command
	Loc        []parser.Range // location of the defining IMPORT command

	Options []KeyValuePairOptional // frontend options used in addition to existing
}

func (i ImportCommand) Location() []parser.Range {
	return i.Loc
}

func (i ImportCommand) Name() string {
	return i.OrigCmd
}

func (i ImportCommand) String() string {
	return i.SourceCode
}

func (i *ImportCommand) AddCommand(cmd Command) {
	i.Commands = append(i.Commands, cmd)
}

func parseImport(req parseRequest) (*ImportCommand, error) {
	stageName, err := parseBuildStageName(req.args)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("failed to parse import [%s]", strings.Join(req.args, " ")))
	}

	flPlatform := req.flags.AddString("platform", "")
	flTarget := req.flags.AddString("target", "")
	flContext := req.flags.AddString("context", "")
	flFilename := req.flags.AddString("file", "")
	flOptions := req.flags.AddStrings("opt")
	if err := req.flags.Parse(); err != nil {
		return nil, err
	}

	var options = make([]KeyValuePairOptional, len(flOptions.StringValues))
	for i, opt := range flOptions.StringValues {
		parts := strings.SplitN(opt, "=", 2)
		if len(parts) == 1 {
			options[i].Key = parts[0]
		} else {
			options[i].Key = parts[0]
			v := parts[1]
			options[i].Value = &v
		}
	}

	code := strings.TrimSpace(req.original)
	return &ImportCommand{
		BaseName:   req.args[0],
		OrigCmd:    req.command,
		StageName:  stageName,
		SourceCode: code,
		Commands:   []Command{},
		Platform:   flPlatform.Value,
		Context:    flContext.Value,
		Target:     flTarget.Value,
		FileName:   flFilename.Value,
		Loc:        req.location,
		Comment:    getComment(req.comments, stageName),
		Options:    options,
	}, nil
}
