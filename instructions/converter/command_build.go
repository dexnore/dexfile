package converter

import (
	"fmt"
	"strings"
)

type CommandBuild struct {
	withNameAndCode
	Stage string
	Args []KeyValuePair
}

func parseBuild(req parseRequest) (cmdBuild *CommandBuild, err error) {
	cmdBuild = &CommandBuild{withNameAndCode: newWithNameAndCode(req)}
	if len(req.args) > 1 {
		return nil, fmt.Errorf("BUILD requires at least one argument")
	}

	cmdBuild.Stage = req.args[0]
	cmdBuild.Args = make([]KeyValuePair, len(req.flags.Args))
	for _, arg := range req.flags.Args {
		if arg == "--" {
			break
		}

		if !strings.HasPrefix(arg, "--") {
			continue
		}

		key, value, ok := strings.Cut(arg, "=")
		if ok {
			cmdBuild.Args = append(cmdBuild.Args, KeyValuePair{
				Key: key,
				Value: value,
			})
		} else {
			cmdBuild.Args = append(cmdBuild.Args, KeyValuePair{
				Key: key,
				Value: "true",
			})
		}
	}

	return cmdBuild, nil
}
