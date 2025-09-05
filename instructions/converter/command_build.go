package converter

import (
	"fmt"
	"strings"
)

type CommandBuild struct {
	withNameAndCode
	Stage string
	Args  []KeyValuePairOptional
}

func parseBuild(req parseRequest) (cmdBuild *CommandBuild, err error) {
	cmdBuild = &CommandBuild{withNameAndCode: newWithNameAndCode(req)}
	if len(req.args) != 1 {
		return nil, fmt.Errorf("BUILD requires single argument")
	}

	cmdBuild.Args = make([]KeyValuePairOptional, 0, len(req.flags.Args))
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
			cmdBuild.Args = append(cmdBuild.Args, KeyValuePairOptional{
				Key:   key,
				Value: &value,
			})
		} else {
			True := "true"
			cmdBuild.Args = append(cmdBuild.Args, KeyValuePairOptional{
				Key:   key,
				Value: &True,
			})
		}
	}

	cmdBuild.Stage = req.args[0]
	return cmdBuild, nil
}
