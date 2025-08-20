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
forloop:
	for i := 0; i < len(ast.Children); i++ {
		n := ast.Children[i]
		cmd, parseErr := ParseInstructionWithLinter(n, lint)
		if parseErr != nil {
			return nil, nil, &parseError{inner: parseErr, node: n}
		}

		// Handle meta commands before the first stage
		if len(stages) == 0 {
			switch c := cmd.(type) {
			case *ConditionIfElse:
				metaCmds = append(metaCmds, c)
				continue forloop
			case *ImportCommand:
				if c.StageName == "" {
					stages = append(stages, c)
					continue forloop
				}
				metaCmds = append(metaCmds, c)
				continue forloop
			case *ArgCommand:
				metaCmds = append(metaCmds, c)
				continue forloop
			case *ConditionIF:
				blockNode := &parser.Node{Children: ast.Children[i:]}
				condBlock, consumedNodes, parseScopedErr := ParseConditional(blockNode, lint)
				if parseScopedErr != nil {
					return nil, nil, parseScopedErr
				}

				metaCmds = append(metaCmds, condBlock)
				i += consumedNodes - 1
				continue forloop
			case *Function:
				blockNode := &parser.Node{Children: ast.Children[i:]}
				funcBlock, consumedNodes, parseScopedErr := ParseFunction(blockNode, lint)
				if parseScopedErr != nil {
					return nil, nil, parseScopedErr
				}

				metaCmds = append(metaCmds, funcBlock)
				i += consumedNodes - 1
				continue forloop
			}
		}

		// Get the current active stage. This will return an error if no stage has been defined yet.
		currentActiveStage, stageErr := CurrentStage(stages)

		// Validate that no instruction (except Stage itself) appears before the first Stage
		if currentActiveStage == nil { // No stages defined yet
			if _, isStage := cmd.(*Stage); !isStage { // If it's not a Stage command
				return nil, nil, parser.WithLocation(errors.Errorf("syntax error: found %T before first stage (expected oneof [ 'from' | 'import' | 'func' ] instruction)", cmd), n.Location())
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
			i += consumedNodes - 1
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
			i += consumedNodes - 1
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
			i += consumedNodes - 1
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
			i += consumedNodes - 1
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
			return nil, nil, parser.WithLocation(errors.Errorf("%T is an unrecognized top-level instruction", cmd), n.Location())
		}
	}

	return stages, metaCmds, nil
}

// ParseConditional is the main function to parse the conditional block
func ParseConditional(ast *parser.Node, lint *linter.Linter) (cond *ConditionIfElse, i int, err error) {
	cond = &ConditionIfElse{withNameAndCode: newWithNameAndCode(newParseRequestFromNode(ast.Children[0]))}
	var (
		inElse      bool
		currentElse *ConditionElse
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
	if _, ok := firstInstruction.(*ConditionIF); !ok {
		return nil, 0, parser.WithLocation(errors.Errorf("conditional block error: block must start with an 'if' instruction, got %T", firstInstruction), firstInstructionNode.Location())
	}
	cond.ConditionIF = firstInstruction.(*ConditionIF)
	i = 1 // Start parsing children from the second node (after the initial IF keyword)
	for i < len(ast.Children) {
		n := ast.Children[i]
		cmd, err := ParseInstructionWithLinter(n, lint)
		if err != nil {
			return nil, i, &parseError{inner: err, node: n}
		}

		switch c := cmd.(type) {
		case *ConditionIF: // Nested IF/ELSE block
			// STRICT REQUIREMENT: currentElse must be initialized if in an else context
			if inElse && currentElse == nil {
				return nil, i, parser.WithLocation(errors.Errorf("parser error: conditional block error: 'else' block not properly initialized before nested 'if' block"), n.Location())
			}

			// The current node 'n' (which is the nested 'if') starts the nested block.
			// Pass the remaining children from the current index onwards to the recursive call.
			blockNode := &parser.Node{Children: ast.Children[i:]}
			nestedCond, consumed, err := ParseConditional(blockNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}

			cond.code += fmt.Sprintf("\n\t%s", nestedCond.String())
			if inElse {
				if err := currentElse.AddCommand(nestedCond); err != nil {
					return nil, i, parser.WithLocation(err, n.Location())
				}
			} else {
				// STRICT REQUIREMENT: Main IF block must not be closed
				if cond.ConditionIF.End {
					return nil, i, parser.WithLocation(errors.Errorf("internal error: cannot add nested IF to a closed IF block"), n.Location())
				}
				if err := cond.AddCommand(nestedCond); err != nil {
					return nil, i, parser.WithLocation(err, n.Location())
				}
			}
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
			continue      // Skip i++ at end of loop, as 'i' has already been updated
		case *ConditionElse: // Encountered an 'else' keyword
			// Close the previous 'else' block if one was open
			if inElse && currentElse != nil {
				if !currentElse.End { // Ensure it's not already ended
					currentElse.EndBlock()
				} else {
					return nil, i, parser.WithLocation(errors.Errorf("conditional block error: inline else blocks are self closing"), n.Location())
				}
			}

			// Mark the main IF block as closed when the first ELSE is encountered.
			if !cond.ConditionIF.End {
				cond.EndBlock()
			}

			// Initialize a new currentElse block
			currentElse = &ConditionElse{}
			cond.ConditionElse = append(cond.ConditionElse, currentElse)
			inElse = true // Transition to the 'else' context
			cond.code += fmt.Sprintf("\n%s", c.String())
		case *EndIf: // Encountered an 'endif' keyword
			// Close the current 'else' block if one was open
			if inElse && currentElse != nil {
				if !currentElse.End { // Ensure it's not already ended
					currentElse.EndBlock()
				} else {
					return nil, i, parser.WithLocation(errors.Errorf("conditional block error: unable to close 'else' block while parsing 'endif'"), n.Location())
				}
			} else { // This means EndIf is for the main IF block
				if !cond.ConditionIF.End { // Ensure it's not already ended
					cond.EndBlock()
				} else {
					return nil, i, parser.WithLocation(errors.Errorf("conditional block error: unable to close 'if' block while parsing 'endif'"), n.Location())
				}
			}
			cond.code += fmt.Sprintf("\n%s", c.String())
			return cond, i + 1, nil // Return, consuming the EndIf instruction (+1)
		case *CommandConatainer:
			ctrBlock := &parser.Node{Children: ast.Children[i:]}
			ctrcmd, consumed, err := ParseContainer(ctrBlock, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			if inElse {
				// STRICT REQUIREMENT: currentElse must be initialized before adding content
				if currentElse == nil {
					return nil, i, parser.WithLocation(errors.Errorf("parser error: conditional block error: 'else' block not properly initialized before command instruction"), n.Location())
				}
				if err := currentElse.AddCommand(ctrcmd); err != nil {
					return nil, i, parser.WithLocation(err, n.Location())
				}
			} else {
				// STRICT REQUIREMENT: Main IF block must not be closed
				if cond.ConditionIF.End {
					return nil, i, parser.WithLocation(errors.Errorf("conditional block error: cannot add command to a closed 'if' block"), n.Location())
				}
				if err := cond.AddCommand(ctrcmd); err != nil {
					return nil, i, parser.WithLocation(err, n.Location())
				}
			}
			i += consumed
			cond.code += fmt.Sprintf("\n\t%s", ctrcmd.String())
		case *CommandFor:
			forBlock := &parser.Node{Children: ast.Children[i:]}
			forcmd, consumed, err := ParseLoop(forBlock, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			if inElse {
				// STRICT REQUIREMENT: currentElse must be initialized before adding content
				if currentElse == nil {
					return nil, i, parser.WithLocation(errors.Errorf("parser error: conditional block error: 'else' block not properly initialized before command instruction"), n.Location())
				}
				if err := currentElse.AddCommand(forcmd); err != nil {
					return nil, i, parser.WithLocation(err, n.Location())
				}
			} else {
				// STRICT REQUIREMENT: Main IF block must not be closed
				if cond.ConditionIF.End {
					return nil, i, parser.WithLocation(errors.Errorf("conditional block error: cannot add command to a closed 'if' block"), n.Location())
				}
				if err := cond.AddCommand(forcmd); err != nil {
					return nil, i, parser.WithLocation(err, n.Location())
				}
			}
			i += consumed
			cond.code += fmt.Sprintf("\n\t%s", forcmd.String())
		case *Function:
			funNode := &parser.Node{Children: ast.Children[i:]}
			fun, consumed, err := ParseFunction(funNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			if inElse {
				// STRICT REQUIREMENT: currentElse must be initialized before adding content
				if currentElse == nil {
					return nil, i, parser.WithLocation(errors.Errorf("parser error: conditional block error: 'else' block not properly initialized before command instruction"), n.Location())
				}
				if err := currentElse.AddCommand(fun); err != nil {
					return nil, i, parser.WithLocation(err, n.Location())
				}
			} else {
				// STRICT REQUIREMENT: Main IF block must not be closed
				if cond.ConditionIF.End {
					return nil, i, parser.WithLocation(errors.Errorf("conditional block error: cannot add command to a closed 'if' block"), n.Location())
				}
				if err := cond.AddCommand(fun); err != nil {
					return nil, i, parser.WithLocation(err, n.Location())
				}
			}
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
			cond.code += fmt.Sprintf("\n\t%s", fun.String())
		case Command:
			if inElse {
				// STRICT REQUIREMENT: currentElse must be initialized before adding content
				if currentElse == nil {
					return nil, i, parser.WithLocation(errors.Errorf("parser error: conditional block error: 'else' block not properly initialized before command instruction"), n.Location())
				}
				if err := currentElse.AddCommand(c); err != nil {
					return nil, i, parser.WithLocation(err, n.Location())
				}
			} else {
				// STRICT REQUIREMENT: Main IF block must not be closed
				if cond.ConditionIF.End {
					return nil, i, parser.WithLocation(errors.Errorf("conditional block error: cannot add command to a closed 'if' block"), n.Location())
				}
				if err := cond.AddCommand(c); err != nil {
					return nil, i, parser.WithLocation(err, n.Location())
				}
			}
			if stringer, ok := c.(fmt.Stringer); ok {
				cond.code += fmt.Sprintf("\n\t%s", stringer.String()) // TODO: add for `FUNC`, `CTR`, `FOR` etc..., instructions too 
			} else {
				cond.code += fmt.Sprintf("\n\t%s %s", c.Name(), "<unknown command>")
			}
		default:
			return nil, i, parser.WithLocation(errors.Errorf("%T is not a recognized instruction type for if/else blocks", cmd), n.Location())
		}
		i++ // Move to the next instruction
	}

	// All blocks must be explicitly closed by now.
	// If the loop finishes without encountering an 'endif' for the outermost block, it's an error.
	if !cond.ConditionIF.End {
		return nil, i, parser.WithLocation(errors.Errorf("conditional block error: main 'if' block not closed with 'endif' or 'else' keyword"), ast.Children[len(ast.Children)-1].Location())
	}
	if inElse && currentElse != nil && !currentElse.End {
		return nil, i, parser.WithLocation(errors.Errorf("conditional block error: last 'else' block not closed with 'endif' or another 'else' keyword"), ast.Children[len(ast.Children)-1].Location())
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
			forcmd.AddCommand(nestedFor)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
			continue      // Skip i++ at end of loop, as 'i' has already been updated
		case *CommandEndFor: // Encountered an 'endif' keyword
			return forcmd, i + 1, nil // Return, consuming the EndIf instruction (+1)
		case *CommandConatainer:
			ctrBlock := &parser.Node{Children: ast.Children[i:]}
			ctrcmd, consumed, err := ParseContainer(ctrBlock, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			forcmd.AddCommand(ctrcmd)
			i += consumed
		case *ConditionIF:
			conditionalNode := &parser.Node{Children: ast.Children[i:]}
			conditional, consumed, err := ParseConditional(conditionalNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			forcmd.AddCommand(conditional)
			i += consumed
		case *Function:
			funNode := &parser.Node{Children: ast.Children[i:]}
			fun, consumed, err := ParseFunction(funNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			forcmd.AddCommand(fun)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
		case Command:
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
			nestedCtr.ParentCtr(ctrcmd)
			ctrcmd.AddCommand(nestedCtr)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
			continue      // Skip i++ at end of loop, as 'i' has already been updated
		case *EndContainer: // Encountered an 'endif' keyword
			return ctrcmd, i + 1, nil // Return, consuming the EndIf instruction (+1)
		case *CommandProcess:
			c.InContainer = *ctrcmd
			ctrcmd.AddCommand(c)
		case *ConditionIF:
			conditionalNode := &parser.Node{Children: ast.Children[i:]}
			conditional, consumed, err := ParseConditional(conditionalNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			ctrcmd.AddCommand(conditional)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
		case *CommandFor:
			forNode := &parser.Node{Children: ast.Children[i:]}
			forcmd, consumed, err := ParseLoop(forNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			ctrcmd.AddCommand(forcmd)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
		case *Function:
			funNode := &parser.Node{Children: ast.Children[i:]}
			fun, consumed, err := ParseFunction(funNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			ctrcmd.AddCommand(fun)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
		case Command:
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
	if v, ok := firstInstruction.(*Function); !ok {
		return nil, 0, parser.WithLocation(errors.Errorf("FUNC block error: block must start with a 'func' instruction, got %T", firstInstruction), firstInstructionNode.Location())
	} else {
		fun = v
		if fun.Action != nil {
			return fun, i + 1, nil
		}
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
			fun.AddCommand(nestedFor)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
			continue      // Skip i++ at end of loop, as 'i' has already been updated
		case *EndFunction: // Encountered an 'endfunc' keyword
			return fun, i + 1, nil // Return, consuming the ENDFUNC instruction (+1)
		case *CommandConatainer:
			ctrBlock := &parser.Node{Children: ast.Children[i:]}
			ctrcmd, consumed, err := ParseContainer(ctrBlock, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			fun.AddCommand(ctrcmd)
			i += consumed
		case *ConditionIF:
			conditionalNode := &parser.Node{Children: ast.Children[i:]}
			conditional, consumed, err := ParseConditional(conditionalNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			fun.AddCommand(conditional)
			i += consumed
		case *CommandFor:
			forNode := &parser.Node{Children: ast.Children[i:]}
			forcmd, consumed, err := ParseLoop(forNode, lint)
			if err != nil {
				return nil, i, err // Propagate error from nested parsing
			}
			fun.AddCommand(forcmd)
			i += consumed // Advance index by the number of nodes consumed by the nested ParseScoped call
		case Command:
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
