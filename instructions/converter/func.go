package converter

import (
	"fmt"
	"strings"
)

type Function struct {
	FuncName string
	Commands []Command
	Args     []KeyValuePairOptional
	Action   *string
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

	for _, arg := range req.flags.Args {
		if arg == "--" {
			break
		}

		if !strings.HasPrefix(arg, "--") {
			continue
		}

		key, value, ok := strings.Cut(arg, "=")
		key = strings.TrimPrefix(key, "--")
		if ok {
			fun.AddArg(KeyValuePairOptional{
				Key:   key,
				Value: &value,
			})
		} else {
			True := "true"
			fun.AddArg(KeyValuePairOptional{
				Key:   key,
				Value: &True,
			})
		}
	}
	return fun, nil
}

func parseEndFunc(req parseRequest) (*EndFunction, error) {
	if len(req.args) > 0 {
		if s := strings.TrimSpace(strings.Join(req.args, " ")); s != "" {
			return nil, &UnknownInstructionError{Instruction: s, Line: req.location[0].Start.Line}
		}
	}
	return &EndFunction{withNameAndCode: newWithNameAndCode(req)}, nil
}
