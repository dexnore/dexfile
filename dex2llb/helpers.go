package dex2llb

func fillDepsAndValidate(allDispatchStates *dispatchStates) error {
	// fill dependencies to stages so unreachable ones can avoid loading image configs
	for _, d := range allDispatchStates.states {
		d.commands = make([]command, len(d.StageCommands()))
		for i, cmd := range d.StageCommands() {
			newCmd, err := toCommand(cmd, allDispatchStates)
			if err != nil {
				return err
			}
			d.commands[i] = newCmd
			for _, src := range newCmd.sources {
				if src != nil {
					d.deps[src] = cmd
					if src.unregistered {
						allDispatchStates.addState(src)
					}
				}
			}
		}
	}

	if err := validateCircularDependency(allDispatchStates.states); err != nil {
		return err
	}

	return nil
}
