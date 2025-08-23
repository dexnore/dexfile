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

	cmdBuild.Stage = req.args[0]
	cmdBuild.Args = make([]KeyValuePairOptional, len(req.flags.Args))
	for _, arg := range req.flags.Args {
		if arg == "--" {
			break
		}

		if !strings.HasPrefix(arg, "--") {
			continue
		}

		key, value, ok := strings.Cut(arg, "=")
		if ok {
			cmdBuild.Args = append(cmdBuild.Args, KeyValuePairOptional{
				Key:   key,
				Value: &value,
			})
		} else {
			cmdBuild.Args = append(cmdBuild.Args, KeyValuePairOptional{
				Key:   key,
			})
		}
	}

	return cmdBuild, nil
}
