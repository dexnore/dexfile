package converter

import (
	"fmt"
	"regexp"
	"strings"
)

type Function struct {
	FuncName string
	Commands []Command
	Args []KeyValuePairOptional
	Action *string
	withNameAndCode
}

type EndFunction struct {
	withNameAndCode
}

func (f *Function) AddCommand(cmd Command) {
	f.Commands = append(f.Commands, cmd)
}

func (f *Function) AddArg(arg KeyValuePairOptional) {
	f.Args = append(f.Args, arg)
}

func parseFunc(req parseRequest) (fun *Function, err error) {
	fun = &Function{withNameAndCode: newWithNameAndCode(req)}
	switch len(req.args) {
	case 2:
		action := strings.ToLower(strings.TrimSpace(req.args[0]))
		fun.Action = &action
		fun.FuncName = req.args[1]
	case 1:
		fun.FuncName = req.args[0]
	default:
		return nil, fmt.Errorf("function name is required")
	}
	if err := req.flags.MustParse(); err != nil {
		return nil, err
	}

	for k, v := range req.flags.flags {
		flagKeyValue := KeyValuePairOptional{Key: k}
		if v != nil {
			flagKeyValue.Value = &v.Value
		}
		fun.AddArg(flagKeyValue)
	}
	return fun, nil
}

func parseEndFunc(req parseRequest) (*EndFunction, error) {
	if len(req.args) > 0 {
		original := regexp.MustCompile(`(?i)^\s*ENDFUNC\s*`).ReplaceAllString(req.original, "")
		for _, heredoc := range req.heredocs {
			original += "\n" + heredoc.Content + heredoc.Name
		}
		if len(original) > 0 {
			return nil, &UnknownInstructionError{Instruction: original, Line: req.location[0].Start.Line}
		}
	}
	return &EndFunction{withNameAndCode: newWithNameAndCode(req)}, nil
}
