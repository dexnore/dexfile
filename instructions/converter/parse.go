// The instructions package contains the definitions of the high-level
// Dexfile commands, as well as low-level primitives for extracting these
// commands from a pre-parsed Abstract Syntax Tree.

package converter

import (
	"fmt"
	"slices"
	"strings"

	"github.com/dexnore/dexfile/command"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/util/suggest"
	"github.com/pkg/errors"
)

func ParseInstruction(node *parser.Node) (v any, err error) {
	return ParseInstructionWithLinter(node, nil)
}

// ParseInstruction converts an AST to a typed instruction (either a command or a build stage beginning when encountering a `FROM` statement)
func ParseInstructionWithLinter(node *parser.Node, lint *linter.Linter) (v any, err error) {
	defer func() {
		if err != nil {
			err = parser.WithLocation(err, node.Location())
		}
	}()
	req := newParseRequestFromNode(node)
	switch strings.ToLower(node.Value) {
	case command.ENV:
		return parseEnv(req)
	case command.MAINTAINER:
		msg := linter.RuleMaintainerDeprecated.Format()
		lint.Run(&linter.RuleMaintainerDeprecated, node.Location(), msg)
		return parseMaintainer(req)
	case command.LABEL:
		return parseLabel(req)
	case command.ADD:
		return parseAdd(req)
	case command.COPY:
		return parseCopy(req)
	case command.FROM:
		if !isLowerCaseStageName(req.args) {
			msg := linter.RuleStageNameCasing.Format(req.args[2])
			lint.Run(&linter.RuleStageNameCasing, node.Location(), msg)
		}
		if !doesFromCaseMatchAsCase(req) {
			msg := linter.RuleFromAsCasing.Format(req.command, req.args[1])
			lint.Run(&linter.RuleFromAsCasing, node.Location(), msg)
		}
		fromCmd, err := parseFrom(req)
		if err != nil {
			return nil, err
		}
		if fromCmd.StageName != "" {
			validateDefinitionDescription("FROM", []string{fromCmd.StageName}, node.PrevComment, node.Location(), lint)
		}
		return fromCmd, nil
	case command.ONBUILD:
		return parseOnBuild(req)
	case command.WORKDIR:
		return parseWorkdir(req)
	case command.RUN:
		return parseRun(req)
	case command.CMD:
		return parseCmd(req)
	case command.HEALTHCHECK:
		return parseHealthcheck(req)
	case command.ENTRYPOINT:
		return parseEntrypoint(req)
	case command.EXPOSE:
		return parseExpose(req)
	case command.USER:
		return parseUser(req)
	case command.VOLUME:
		return parseVolume(req)
	case command.STOPSIGNAL:
		return parseStopSignal(req)
	case command.ARG:
		argCmd, err := parseArg(req)
		if err != nil {
			return nil, err
		}
		argKeys := []string{}
		for _, arg := range argCmd.Args {
			argKeys = append(argKeys, arg.Key)
		}
		validateDefinitionDescription("ARG", argKeys, node.PrevComment, node.Location(), lint)
		return argCmd, nil
	case command.SHELL:
		return parseShell(req)
	case command.IF:
		return parseIf(req)
	case command.ELSE:
		return parseElse(req)
	case command.ENDIF:
		return parseEndIf(req)
	case command.EXEC:
		return parseExec(req)
	case command.IMPORT:
		return parseImport(req)
	case command.FOR:
		return parseFor(req)
	case command.ENDFOR:
		return parseEndFor(req)
	case command.CTR:
		return parseCtr(req)
	case command.ENDCTR:
		return parseEndCtr(req)
	case command.PROC:
		return parseProc(req)
	case command.FUNC:
		return parseFunc(req)
	case command.ENDFUNC:
		return parseEndFunc(req)
	case command.BUILD:
		return parseBuild(req)
	}
	return nil, suggest.WrapError(&UnknownInstructionError{Instruction: node.Value, Line: node.StartLine}, node.Value, allInstructionNames(), false)
}

// ParseCommand converts an AST to a typed Command
func ParseCommand(node *parser.Node) (Command, error) {
	s, err := ParseInstruction(node)
	if err != nil {
		return nil, err
	}
	if c, ok := s.(Command); ok {
		return c, nil
	}
	return nil, parser.WithLocation(errors.Errorf("%T is not a command type", s), node.Location())
}

type Adder interface {
	AddCommand(cmd Command)
	Location() []parser.Range
	Name() string
	String() string
}

// Parse a Dexfile into a collection of buildable stages.
// metaArgs is a collection of ARG instructions that occur before the first FROM.
func Parse(ast *parser.Node, lint *linter.Linter) (stages []Adder, metaCmds []Command, err error) {
	for i := 0; i < len(ast.Children); i++ {
		n := ast.Children[i]
		cmd, parseErr := ParseInstructionWithLinter(n, lint)
		if parseErr != nil {
			return nil, nil, &parseError{inner: parseErr, node: n}
		}

		// Get the current active stage. This will return an error if no stage has been defined yet.
		currentActiveStage, stageErr := CurrentStage(stages)

		// Validate that no instruction (except Stage itself) appears before the first Stage
		if currentActiveStage == nil { // No stages defined yet
			if _, isStage := cmd.(*Stage); !isStage { // If it's not a Stage command
				switch cmd := cmd.(type) {
				case *ConditionIF:
					blockNode := &parser.Node{Children: ast.Children[i:]}
					condBlock, consumedNodes, parseScopedErr := ParseConditional(blockNode, lint)
					if parseScopedErr != nil {
						return nil, nil, parseScopedErr
					}

					metaCmds = append(metaCmds, condBlock)
					i += consumedNodes
				case *CommandFor:
					blockNode := &parser.Node{Children: ast.Children[i:]}
					forBlock, consumedNodes, parseScopedErr := ParseLoop(blockNode, lint)
					if parseScopedErr != nil {
						return nil, nil, parseScopedErr
					}

					metaCmds = append(metaCmds, forBlock)
					i += consumedNodes
				case *CommandConatainer:
					blockNode := &parser.Node{Children: ast.Children[i:]}
					ctrBlock, consumedNodes, parseScopedErr := ParseContainer(blockNode, lint)
					if parseScopedErr != nil {
						return nil, nil, parseScopedErr
					}

					metaCmds = append(metaCmds, ctrBlock)
					i += consumedNodes
				case *Function:
					blockNode := &parser.Node{Children: ast.Children[i:]}
					funcBlock, consumedNodes, parseScopedErr := ParseFunction(blockNode, lint)
					if parseScopedErr != nil {
						return nil, nil, parseScopedErr
					}

					metaCmds = append(metaCmds, funcBlock)
					i += consumedNodes
				case *ImportCommand:
					if cmd.StageName == "" {
						stages = append(stages, cmd)
						continue
					}
					metaCmds = append(metaCmds, cmd)
				case *ConditionElse, *EndContainer, *EndFunction, *EndIf:
					err = fmt.Errorf("unexpected %+v at top level", cmd)
					if cmd, ok := cmd.(interface{ Location() []parser.Range }); ok {
						err = parser.WithLocation(err, cmd.Location())
					}
					return nil, nil, err
				case Command:
					metaCmds = append(metaCmds, cmd)
				default:
					return nil, nil, parser.WithLocation(errors.Errorf("syntax error: found %T before first stage (expected oneof [ 'from' | 'import' | 'func' ] instruction)", cmd), n.Location())
				}
				continue
			}
		}

		switch c := cmd.(type) {
		case *Stage:
			stages = append(stages, c) // Add the new stage
		case *ImportCommand:
			stages = append(stages, c) // Add the new stage
		case *Function:
			if c.Action != nil {
				// Ensure there's an active stage to attach the command to
				if stageErr != nil {
					return nil, nil, parser.WithLocation(stageErr, n.Location())
				}
				currentActiveStage.AddCommand(c)
				continue
			}
			// Ensure there's an active stage to attach the conditional block to
			if stageErr != nil {
				return nil, nil, parser.WithLocation(stageErr, n.Location())
			}

			// Parse the if/else block using ParseScoped
			// Pass the remainder of the AST starting from the current node 'n' (which is the 'if' keyword)
			blockNode := &parser.Node{Children: ast.Children[i:]}
			funcBlock, consumedNodes, parseScopedErr := ParseFunction(blockNode, lint)
			if parseScopedErr != nil {
				return nil, nil, parseScopedErr
			}

			metaCmds = append(metaCmds, funcBlock)

			// Adjust the loop index. ParseScoped consumed 'consumedNodes' from its input (which started at 'i').
			// The for loop will automatically increment 'i' by 1 at the end of this iteration,
			// so we need to advance 'i' by (consumedNodes - 1).
			i += consumedNodes
		case *CommandConatainer:
			// Ensure there's an active stage to attach the conditional block to
			if stageErr != nil {
				return nil, nil, parser.WithLocation(stageErr, n.Location())
			}

			// Parse the if/else block using ParseScoped
			// Pass the remainder of the AST starting from the current node 'n' (which is the 'if' keyword)
			blockNode := &parser.Node{Children: ast.Children[i:]}
			ctrBlock, consumedNodes, parseScopedErr := ParseContainer(blockNode, lint)
			if parseScopedErr != nil {
				return nil, nil, parseScopedErr
			}

			currentActiveStage.AddCommand(ctrBlock)

			// Adjust the loop index. ParseScoped consumed 'consumedNodes' from its input (which started at 'i').
			// The for loop will automatically increment 'i' by 1 at the end of this iteration,
			// so we need to advance 'i' by (consumedNodes - 1).
			i += consumedNodes
		case *CommandFor:
			// Ensure there's an active stage to attach the conditional block to
			if stageErr != nil {
				return nil, nil, parser.WithLocation(stageErr, n.Location())
			}

			// Parse the if/else block using ParseScoped
			// Pass the remainder of the AST starting from the current node 'n' (which is the 'if' keyword)
			blockNode := &parser.Node{Children: ast.Children[i:]}
			forBlock, consumedNodes, parseScopedErr := ParseLoop(blockNode, lint)
			if parseScopedErr != nil {
				return nil, nil, parseScopedErr
			}

			currentActiveStage.AddCommand(forBlock)

			// Adjust the loop index. ParseScoped consumed 'consumedNodes' from its input (which started at 'i').
			// The for loop will automatically increment 'i' by 1 at the end of this iteration,
			// so we need to advance 'i' by (consumedNodes - 1).
			i += consumedNodes
		case *ConditionIF:
			// Ensure there's an active stage to attach the conditional block to
			if stageErr != nil {
				return nil, nil, parser.WithLocation(stageErr, n.Location())
			}

			// Parse the if/else block using ParseScoped
			// Pass the remainder of the AST starting from the current node 'n' (which is the 'if' keyword)
			blockNode := &parser.Node{Children: ast.Children[i:]}
			condBlock, consumedNodes, parseScopedErr := ParseConditional(blockNode, lint)
			if parseScopedErr != nil {
				return nil, nil, parseScopedErr
			}

			currentActiveStage.AddCommand(condBlock)

			// Adjust the loop index. ParseScoped consumed 'consumedNodes' from its input (which started at 'i').
			// The for loop will automatically increment 'i' by 1 at the end of this iteration,
			// so we need to advance 'i' by (consumedNodes - 1).
			i += consumedNodes
		case *ConditionElse, *EndIf, *CommandEndFor, *EndContainer, *EndFunction:
			// STRICT REQUIREMENT: These are handled internally by ParseScoped and
			// should NOT be encountered at the top level of the dexfile parsing.
			printstmt := fmt.Sprintf("%T", cmd)
			if cmd, ok := cmd.(Command); ok {
				printstmt = cmd.Name()
			}
			return nil, nil, parser.WithLocation(errors.Errorf("syntax error: unexpected %s at top level", printstmt), n.Location())
		case Command:
			// Ensure there's an active stage to attach the command to
			if stageErr != nil {
				return nil, nil, parser.WithLocation(stageErr, n.Location())
			}
			currentActiveStage.AddCommand(c)
		default:
			// Catch any other unexpected instruction types
			return nil, nil, parser.WithLocation(errors.Errorf("%+v is an unrecognized top-level instruction", cmd), n.Location())
		}
	}

	return stages, metaCmds, nil
}

// ParseConditional is the main function to parse the conditional block
func ParseConditional(ast *parser.Node, lint *linter.Linter) (cond *ConditionIfElse, i int, err error) {
	cond = &ConditionIfElse{withNameAndCode: newWithNameAndCode(newParseRequestFromNode(ast.Children[0]))}
	var (
		currentCond interface {
			EndBlock() error
			AddCommand(cmd Command) error
		}
	)

	// A conditional block MUST start with an IF command.
	if len(ast.Children) == 0 {
		return nil, 0, errors.New("conditional block error: expected 'if' instruction")
	}

	firstInstructionNode := ast.Children[0]
	firstInstruction, err := ParseInstructionWithLinter(firstInstructionNode, lint)
	if err != nil {
		return nil, 0, &parseError{inner: err, node: firstInstructionNode}
	}
	switch firstInstruction := firstInstruction.(type) {
	case *ConditionIF:
		cond.ConditionIF = firstInstruction
		currentCond = cond.ConditionIF
	default:
		return nil, 0, parser.WithLocation(errors.Errorf("conditional block error: block must start with an 'if' instruction, got %T", firstInstruction), firstInstructionNode.Location())
	}
	i = 1 // Start parsing children from the second node (after the initial IF keyword)
	for i < len(ast.Children) {
		n := ast.Children[i]
		cmd, err := ParseInstructionWithLinter(n, lint)
		if err != nil {
			return nil, i, &parseError{inner: err, node: n}
		}

		switch c := cmd.(type) {
		case *ConditionIF: // Nested IF/ELSE block
			// The current node 'n' (which is the nested 'if') starts the nested block.
			// Pass the remaining children from the current index onwards to the recursive call.
			blockNode := &parser.Node{Children: ast.Children[i:]}
			nestedCond, consumed, err := ParseConditional(blockNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}

			for _, str := range strings.Split(c.String(), "\n") {
				cond.code += fmt.Sprintf("\n\t%s", str)
			}
			if err := currentCond.AddCommand(nestedCond); err != nil {
				return nil, i, parser.WithLocation(err, n.Location())
			}
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
			continue      // Skip i++ at end of loop, as 'i' has already been updated
		case *ConditionElse: // Encountered an 'else' keyword
			// Close the previous 'else' block if one was open
			if err := currentCond.EndBlock(); err != nil {
				return nil, i, err
			}

			// Initialize a new currentElse block
			currentCond = c
			cond.ConditionElse = append(cond.ConditionElse, c)
			for i, str := range strings.Split(c.String(), "\n") {
				if i == 0 {
					cond.code += fmt.Sprintf("\n%s", str)
				} else {
					cond.code += fmt.Sprintf("\n\t%s", str)
				}
			}
		case *EndIf: // Encountered an 'endif' keyword
			// Close the current 'else' block if one was open
			if err := currentCond.EndBlock(); err != nil {
				return nil, i, err
			}
			for _, str := range strings.Split(c.String(), "\n") {
				cond.code += fmt.Sprintf("\n%s", str)
			}
			return cond, i, nil // Return, consuming the EndIf instruction (+1)
		case *CommandConatainer:
			ctrBlock := &parser.Node{Children: ast.Children[i:]}
			ctrcmd, consumed, err := ParseContainer(ctrBlock, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}

			if err := currentCond.AddCommand(ctrcmd); err != nil {
				return nil, i, parser.WithLocation(err, n.Location())
			}
			i += consumed
			for _, str := range strings.Split(c.String(), "\n") {
				cond.code += fmt.Sprintf("\n\t%s", str)
			}
		case *CommandFor:
			forBlock := &parser.Node{Children: ast.Children[i:]}
			forcmd, consumed, err := ParseLoop(forBlock, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}

			if err := currentCond.AddCommand(forcmd); err != nil {
				return nil, i, parser.WithLocation(err, n.Location())
			}
			i += consumed
			for _, str := range strings.Split(c.String(), "\n") {
				cond.code += fmt.Sprintf("\n\t%s", str)
			}
		case *Function:
			funNode := &parser.Node{Children: ast.Children[i:]}
			fun, consumed, err := ParseFunction(funNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			if err := currentCond.AddCommand(fun); err != nil {
				return nil, i, parser.WithLocation(err, n.Location())
			}
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
			for _, str := range strings.Split(c.String(), "\n") {
				cond.code += fmt.Sprintf("\n\t%s", str)
			}
		case *CommandEndFor, *EndContainer, *EndFunction:
			// STRICT REQUIREMENT: These are handled internally by ParseScoped and
			// should NOT be encountered at the top level of the dexfile parsing.
			printstmt := fmt.Sprintf("%T", cmd)
			if cmd, ok := cmd.(Command); ok {
				printstmt = cmd.Name()
			}
			return nil, i, parser.WithLocation(errors.Errorf("syntax error: unexpected %s at top level", printstmt), n.Location())
		case Command:
			if err := currentCond.AddCommand(c); err != nil {
				return nil, i, parser.WithLocation(err, n.Location())
			}
			if stringer, ok := c.(fmt.Stringer); ok {
				for _, str := range strings.Split(stringer.String(), "\n") {
					cond.code += fmt.Sprintf("\n\t%s", str)
				}
			} else {
				cond.code += fmt.Sprintf("\n\t%s %s", c.Name(), "<unknown command>")
			}
			// return cond, i, fmt.Errorf("%+v", printStr(ast.Children[i+1:]...))
		default:
			return nil, i, parser.WithLocation(errors.Errorf("%T is not a recognized instruction type for if/else blocks", cmd), n.Location())
		}
		i++ // Move to the next instruction
	}

	// All blocks must be explicitly closed by now.
	// If the loop finishes without encountering an 'endif' for the outermost block, it's an error.
	if currentCond.EndBlock() == nil {
		return cond, i, parser.WithLocation(errors.Errorf("conditional block error: no end token found"), ast.Children[len(ast.Children)-1].Location())
	}

	return cond, i, parser.WithLocation(errors.Errorf("conditional block error: unknown error occured"), ast.Children[len(ast.Children)-1].Location())
}

// ParseLoop is the main function to parse the conditional block
func ParseLoop(ast *parser.Node, lint *linter.Linter) (forcmd *CommandFor, i int, err error) {
	forcmd = &CommandFor{}
	// A conditional block MUST start with an IF command.
	if len(ast.Children) == 0 {
		return nil, 0, errors.New("FOR block error: expected 'for' instruction")
	}

	firstInstructionNode := ast.Children[0]
	firstInstruction, err := ParseInstructionWithLinter(firstInstructionNode, lint)
	if err != nil {
		return nil, 0, &parseError{inner: err, node: firstInstructionNode}
	}
	if v, ok := firstInstruction.(*CommandFor); !ok {
		return nil, 0, parser.WithLocation(errors.Errorf("FOR block error: block must start with a 'for' instruction, got %T", firstInstruction), firstInstructionNode.Location())
	} else {
		forcmd = v
	}
	i = 1 // Start parsing children from the second node (after the initial IF keyword)
	for i < len(ast.Children) {
		n := ast.Children[i]
		cmd, err := ParseInstructionWithLinter(n, lint)
		if err != nil {
			return nil, i, &parseError{inner: err, node: n}
		}

		switch c := cmd.(type) {
		case *CommandFor: // Nested IF/ELSE block
			// The current node 'n' (which is the nested 'if') starts the nested block.
			// Pass the remaining children from the current index onwards to the recursive call.
			blockNode := &parser.Node{Children: ast.Children[i:]}
			nestedFor, consumed, err := ParseLoop(blockNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(nestedFor.String(), "\n") {
				forcmd.code += fmt.Sprintf("\n\t%s", str)
			}
			forcmd.AddCommand(nestedFor)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
			continue      // Skip i++ at end of loop, as 'i' has already been updated
		case *CommandEndFor: // Encountered an 'endif' keyword
			forcmd.code += fmt.Sprintf("\n%s", c.String())
			return forcmd, i, nil // Return, consuming the EndIf instruction (+1)
		case *CommandConatainer:
			ctrBlock := &parser.Node{Children: ast.Children[i:]}
			ctrcmd, consumed, err := ParseContainer(ctrBlock, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(ctrcmd.String(), "\n") {
				forcmd.code += fmt.Sprintf("\n\t%s", str)
			}
			forcmd.AddCommand(ctrcmd)
			i += consumed
		case *ConditionIF:
			conditionalNode := &parser.Node{Children: ast.Children[i:]}
			conditional, consumed, err := ParseConditional(conditionalNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(conditional.String(), "\n") {
				forcmd.code += fmt.Sprintf("\n\t%s", str)
			}
			forcmd.AddCommand(conditional)
			i += consumed
		case *Function:
			funNode := &parser.Node{Children: ast.Children[i:]}
			fun, consumed, err := ParseFunction(funNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(fun.String(), "\n") {
				forcmd.code += fmt.Sprintf("\n\t%s", str)
			}
			forcmd.AddCommand(fun)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
		case *ConditionElse, *EndIf, *EndContainer, *EndFunction:
			// STRICT REQUIREMENT: These are handled internally by ParseScoped and
			// should NOT be encountered at the top level of the dexfile parsing.
			printstmt := fmt.Sprintf("%T", cmd)
			if cmd, ok := cmd.(Command); ok {
				printstmt = cmd.Name()
			}
			return nil, i, parser.WithLocation(errors.Errorf("syntax error: unexpected %s at top level", printstmt), n.Location())
		case Command:
			if stringer, ok := c.(fmt.Stringer); ok {
				for _, str := range strings.Split(stringer.String(), "\n") {
					forcmd.code += fmt.Sprintf("\n\t%s", str)
				}
			} else {
				forcmd.code += fmt.Sprintf("\n\t%s %s", c.Name(), "<unknown command>")
			}
			forcmd.AddCommand(c)
		default:
			return nil, i, parser.WithLocation(errors.Errorf("%T is not a recognized instruction type for 'for' blocks", cmd), n.Location())
		}
		i++ // Move to the next instruction
	}

	return forcmd, i, parser.WithLocation(errors.Errorf("FOR block error: no end token found"), ast.Children[len(ast.Children)-1].Location())
}

// ParseLoop is the main function to parse the conditional block
func ParseContainer(ast *parser.Node, lint *linter.Linter) (ctrcmd *CommandConatainer, i int, err error) {
	ctrcmd = &CommandConatainer{}
	// A conditional block MUST start with an IF command.
	if len(ast.Children) == 0 {
		return nil, 0, errors.New("CTR block error: expected 'ctr' instruction")
	}

	firstInstructionNode := ast.Children[0]
	firstInstruction, err := ParseInstructionWithLinter(firstInstructionNode, lint)
	if err != nil {
		return nil, 0, &parseError{inner: err, node: firstInstructionNode}
	}
	if v, ok := firstInstruction.(*CommandConatainer); !ok {
		return nil, 0, parser.WithLocation(errors.Errorf("CTR block error: block must start with a 'ctr' instruction, got %T", firstInstruction), firstInstructionNode.Location())
	} else {
		ctrcmd = v
	}
	i = 1 // Start parsing children from the second node (after the initial IF keyword)
	for i < len(ast.Children) {
		n := ast.Children[i]
		cmd, err := ParseInstructionWithLinter(n, lint)
		if err != nil {
			return nil, i, &parseError{inner: err, node: n}
		}

		switch c := cmd.(type) {
		case *CommandConatainer: // Nested IF/ELSE block
			// The current node 'n' (which is the nested 'if') starts the nested block.
			// Pass the remaining children from the current index onwards to the recursive call.
			blockNode := &parser.Node{Children: ast.Children[i:]}
			nestedCtr, consumed, err := ParseContainer(blockNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(nestedCtr.String(), "\n") {
				ctrcmd.code += fmt.Sprintf("\n\t%s", str)
			}
			nestedCtr.ParentCtr(ctrcmd)
			ctrcmd.AddCommand(nestedCtr)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
			continue      // Skip i++ at end of loop, as 'i' has already been updated
		case *EndContainer: // Encountered an 'endif' keyword
			for _, str := range strings.Split(c.String(), "\n") {
				ctrcmd.code += fmt.Sprintf("\n%s", str)
			}
			return ctrcmd, i, nil // Return, consuming the EndIf instruction (+1)
		case *CommandProcess:
			for _, str := range strings.Split(c.String(), "\n") {
				ctrcmd.code += fmt.Sprintf("\n\t%s", str)
			}
			c.InContainer = *ctrcmd
			ctrcmd.AddCommand(c)
		case *ConditionIF:
			conditionalNode := &parser.Node{Children: ast.Children[i:]}
			conditional, consumed, err := ParseConditional(conditionalNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(conditional.String(), "\n") {
				ctrcmd.code += fmt.Sprintf("\n\t%s", str)
			}
			ctrcmd.AddCommand(conditional)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
		case *CommandFor:
			forNode := &parser.Node{Children: ast.Children[i:]}
			forcmd, consumed, err := ParseLoop(forNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(forcmd.String(), "\n") {
				ctrcmd.code += fmt.Sprintf("\n\t%s", str)
			}
			ctrcmd.AddCommand(forcmd)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
		case *Function:
			funNode := &parser.Node{Children: ast.Children[i:]}
			fun, consumed, err := ParseFunction(funNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(fun.String(), "\n") {
				ctrcmd.code += fmt.Sprintf("\n\t%s", str)
			}
			ctrcmd.AddCommand(fun)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
		case *ConditionElse, *EndIf, *CommandEndFor, *EndFunction:
			// STRICT REQUIREMENT: These are handled internally by ParseScoped and
			// should NOT be encountered at the top level of the dexfile parsing.
			printstmt := fmt.Sprintf("%T", cmd)
			if cmd, ok := cmd.(Command); ok {
				printstmt = cmd.Name()
			}
			return nil, i, parser.WithLocation(errors.Errorf("syntax error: unexpected %s at top level", printstmt), n.Location())
		case Command:
			if stringer, ok := c.(fmt.Stringer); ok {
				for _, str := range strings.Split(stringer.String(), "\n") {
					ctrcmd.code += fmt.Sprintf("\n\t%s", str)
				}
			} else {
				ctrcmd.code += fmt.Sprintf("\n\t%s %s", c.Name(), "<unknown command>")
			}
			ctrcmd.AddCommand(c)
		default:
			return nil, i, parser.WithLocation(errors.Errorf("%T is not a recognized instruction type for 'ctr' blocks", cmd), n.Location())
		}
		i++ // Move to the next instruction
	}

	return ctrcmd, i, parser.WithLocation(errors.Errorf("CTR block error: no end token found"), ast.Children[len(ast.Children)-1].Location())
}

// ParseLoop is the main function to parse the conditional block
func ParseFunction(ast *parser.Node, lint *linter.Linter) (fun *Function, i int, err error) {
	fun = &Function{}
	// A Function block MUST start with an FUNC command.
	if len(ast.Children) == 0 {
		return nil, 0, errors.New("Function block error: expected 'func' instruction")
	}

	firstInstructionNode := ast.Children[0]
	firstInstruction, err := ParseInstructionWithLinter(firstInstructionNode, lint)
	if err != nil {
		return nil, 0, &parseError{inner: err, node: firstInstructionNode}
	}
	switch firstInstruction := firstInstruction.(type) {
	case *Function:
		fun = firstInstruction
		if fun.Action != nil {
			return fun, i, nil
		}
	default:
		return nil, 0, parser.WithLocation(errors.Errorf("FUNC block error: block must start with a 'func' instruction, got %T", firstInstruction), firstInstructionNode.Location())
	}
	i = 1 // Start parsing children from the second node (after the initial IF keyword)
	for i < len(ast.Children) {
		n := ast.Children[i]
		cmd, err := ParseInstructionWithLinter(n, lint)
		if err != nil {
			return nil, i, &parseError{inner: err, node: n}
		}

		switch c := cmd.(type) {
		case *Function: // Nested IF/ELSE block
			// The current node 'n' (which is the nested 'if') starts the nested block.
			// Pass the remaining children from the current index onwards to the recursive call.
			blockNode := &parser.Node{Children: ast.Children[i:]}
			nestedFor, consumed, err := ParseFunction(blockNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(nestedFor.String(), "\n") {
				fun.code += fmt.Sprintf("\n\t%s", str)
			}
			fun.AddCommand(nestedFor)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
			continue      // Skip i++ at end of loop, as 'i' has already been updated
		case *EndFunction: // Encountered an 'endfunc' keyword
			for _, str := range strings.Split(c.String(), "\n") {
				fun.code += fmt.Sprintf("\n%s", str)
			}
			return fun, i, nil // Return, consuming the ENDFUNC instruction (+1)
		case *CommandConatainer:
			ctrBlock := &parser.Node{Children: ast.Children[i:]}
			ctrcmd, consumed, err := ParseContainer(ctrBlock, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(ctrcmd.String(), "\n") {
				fun.code += fmt.Sprintf("\n\t%s", str)
			}
			fun.AddCommand(ctrcmd)
			i += consumed
		case *ConditionIF:
			conditionalNode := &parser.Node{Children: ast.Children[i:]}
			conditional, consumed, err := ParseConditional(conditionalNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(conditional.String(), "\n") {
				fun.code += fmt.Sprintf("\n\t%s", str)
			}
			fun.AddCommand(conditional)
			i += consumed
		case *CommandFor:
			forNode := &parser.Node{Children: ast.Children[i:]}
			forcmd, consumed, err := ParseLoop(forNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			for _, str := range strings.Split(forcmd.String(), "\n") {
				fun.code += fmt.Sprintf("\n\t%s", str)
			}
			fun.AddCommand(forcmd)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
		case *ConditionElse, *EndIf, *CommandEndFor, *EndContainer:
			// STRICT REQUIREMENT: These are handled internally by ParseScoped and
			// should NOT be encountered at the top level of the dexfile parsing.
			printstmt := fmt.Sprintf("%T", cmd)
			if cmd, ok := cmd.(Command); ok {
				printstmt = cmd.Name()
			}
			return nil, i, parser.WithLocation(errors.Errorf("syntax error: unexpected %s at top level", printstmt), n.Location())
		case Command:
			if stringer, ok := c.(fmt.Stringer); ok {
				for _, str := range strings.Split(stringer.String(), "\n") {
					fun.code += fmt.Sprintf("\n\t%s", str)
				}
			} else {
				fun.code += fmt.Sprintf("\n\t%s %s", c.Name(), "<unknown command>")
			}
			fun.AddCommand(c)
		default:
			return nil, i, parser.WithLocation(errors.Errorf("%T is not a recognized instruction type for 'func' blocks", cmd), n.Location())
		}
		i++ // Move to the next instruction
	}

	return fun, i, parser.WithLocation(errors.Errorf("FUNC block error: no end token found"), ast.Children[len(ast.Children)-1].Location())
}

func getComment(comments []string, name string) string {
	if name == "" {
		return ""
	}
	for _, line := range comments {
		if after, ok := strings.CutPrefix(line, name+" "); ok {
			return after
		}
	}
	return ""
}

func allInstructionNames() []string {
	out := make([]string, len(command.Instructions))
	i := 0
	for name := range command.Instructions {
		out[i] = strings.ToUpper(name)
		i++
	}
	return out
}

func isLowerCaseStageName(cmdArgs []string) bool {
	if len(cmdArgs) != 3 {
		return true
	}
	stageName := cmdArgs[2]
	return stageName == strings.ToLower(stageName)
}

func doesFromCaseMatchAsCase(req parseRequest) bool {
	if len(req.args) < 3 {
		return true
	}
	// consistent casing for the command is handled elsewhere.
	// If the command is not consistent, there's no need to
	// add an additional lint warning for the `as` argument.
	fromHasLowerCasing := req.command == strings.ToLower(req.command)
	fromHasUpperCasing := req.command == strings.ToUpper(req.command)
	if !fromHasLowerCasing && !fromHasUpperCasing {
		return true
	}

	if fromHasLowerCasing {
		return req.args[1] == strings.ToLower(req.args[1])
	}
	return req.args[1] == strings.ToUpper(req.args[1])
}

func validateDefinitionDescription(instruction string, argKeys []string, descComments []string, location []parser.Range, lint *linter.Linter) {
	if len(descComments) == 0 || len(argKeys) == 0 {
		return
	}
	descCommentParts := strings.Split(descComments[len(descComments)-1], " ")
	if slices.Contains(argKeys, descCommentParts[0]) {
		return
	}
	exampleKey := argKeys[0]
	if len(argKeys) > 1 {
		exampleKey = "<arg_key>"
	}

	msg := linter.RuleInvalidDefinitionDescription.Format(instruction, exampleKey)
	lint.Run(&linter.RuleInvalidDefinitionDescription, location, msg)
}
