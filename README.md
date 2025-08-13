# Dexfile Reference

Welcome to the comprehensive Dexfile Reference. Dexfile is a BuildKit frontend that **extends Dockerfile syntax** with additional instructions for advanced, flexible, and modular build workflows. All standard Dockerfile commands and flags are supported; you may use them alongside Dexfile-specific features. This document is the definitive reference for all supported instructions, argument forms, and flags.

---

## Enabling Dexfile Syntax

To use Dexfile syntax, ensure your Dexfile starts with:
```
# syntax=docker.io/dexnore/dexfile:latest
```

Dexfile supports an ignore file named `.dexnore`. This file works analogously to `.dockerignore` for Dockerfile, allowing you to specify files and directories to exclude from the build context, thus reducing context size and improving build performance.

---

## Table of Contents

- [Standard Dockerfile Instructions](#standard-dockerfile-instructions)
- [Dexfile-Specific Instructions](#dexfile-specific-instructions)
  - [IMPORT](#import)
  - [CTR / ENDCTR](#ctr--endctr)
  - [PROC](#proc)
  - [IF / ELSE IF / ELSE / ENDIF](#if--else-if--else--endif)
  - [FOR / ENDFOR](#for--endfor)
  - [FUNC / ENDFUNC / FUNC CALL](#func--endfunc--func-call)
  - [EXEC](#exec)
- [General Notes](#general-notes)

---

## Standard Dockerfile Instructions

Dexfile supports **all standard Dockerfile instructions** and their flags, including:

- `FROM`
- `RUN`
- `CMD`
- `LABEL`
- `MAINTAINER`
- `EXPOSE`
- `ENV`
- `ADD`
- `COPY`
- `ENTRYPOINT`
- `VOLUME`
- `USER`
- `WORKDIR`
- `ARG`
- `ONBUILD`
- `STOPSIGNAL`
- `HEALTHCHECK`
- `SHELL`

All arguments, options, and flags available in Dockerfile are valid in Dexfile.

---

## Dexfile-Specific Instructions

### IMPORT

Import external resources into the build. Supported source types include local directories, Docker/OCI images, Git repositories, HTTP(S) URLs, and frontend-specific inputs.

**Syntax**
```
IMPORT [--platform=<platform>] [--target=<target>] [--file=<path>] [--opt=<key>=<value>] <source> AS <alias>
```

**Arguments and Flags:**
- `<source>`: URI of the resource to import.
  - `local:<path>`
  - `docker-image://<image>`
  - `oci-layout://<path>`
  - `inputs:<name>`
  - `git:<url>`
  - `https://<url>`
- `AS <alias>`: Required. Name to refer to the imported resource.
- `--platform=<platform>`: (Optional) Set target platform for the imported stage.
- `--target=<target>`: (Optional) Target stage of the imported Dexfile/Dockerfile/other frontend.
- `--file=<path>`: (Optional) Path to a frontend definition file (Dexfile, Dockerfile, etc.).
- `--opt=<key>=<value>`: (Optional, repeatable) Set frontend options passed to the imported frontend.

---

### CTR / ENDCTR

Define a block where instructions are executed inside a specific imported container image.  
The `CTR` instruction creates an **ephemeral container** for the duration of the block.

**Syntax**
```
CTR --from=<image_alias>
    <instructions>...
ENDCTR
```

**Flags:**
- `--from=<image_alias>`: Required. Alias of an image imported with `IMPORT`.

---

### PROC

Run a command as a process inside the active container of a `CTR` block. Only valid inside a CTR block.

**Syntax**
```
PROC <command> [args...] [--timeout=<duration>]
```

**Arguments and Flags:**
- `<command>`: Command to execute inside the container.
- `--timeout=<duration>`: (Optional) Maximum execution duration for the process. Defaults to `10m`. After timeout, the ephemeral container is removed.

---

### IF / ELSE IF / ELSE / ENDIF

Conditional execution of instructions depending on the exit code of a test command.

**Syntax**
```
IF [RUN | EXEC | PROC] <command> [--timeout=<duration>]
    <instructions>...
[ELSE IF [RUN | EXEC | PROC] <command> [--timeout=<duration>]]
    <instructions>...
[ELSE]
    <instructions>...
ENDIF
```

**Arguments and Flags:**
- `[RUN | EXEC | PROC] <command>`: Specify how to execute the condition.
  - `RUN <command>`: Run command in current stage
  - `EXEC <command>`: Run command in an ephemeral container; expects buildkit-supported protobuf state in stdout
  - `PROC <command>`: Run command inside the current CTR block
- `--timeout=<duration>`: (Optional) Maximum execution duration. Defaults to `10m`. After timeout, the ephemeral container is removed.

---

### FOR / ENDFOR

Iterate over matches from a command's output (with optional delimiter regex).

**Syntax**
```
FOR <variable> IN [RUN | EXEC] <command> [args...] [--delim=<regex>] [--timeout=<duration>]
  <instructions>...
ENDFOR
```

**Arguments and Flags:**
- `<variable>`: Name of the loop variable.
- `IN [RUN | EXEC] <command>`: Source command for producing iteration values.
- `--delim=<regex>`: (Optional) Regular expression to match output delimiters (used to split stdout of the command for each loop iteration).
- `--timeout=<duration>`: (Optional) Maximum execution duration for the command. Defaults to `10m`. Ephemeral container is removed after timeout.

---

### FUNC / ENDFUNC / FUNC CALL

Define and call reusable functions (instruction blocks).

**Syntax**
```
FUNC <function_name> [--<arg-key>=<arg-value> ...]
    <instructions>...
ENDFUNC

FUNC CALL <function_name> [--<arg-key>=<arg-value> ...]
```

**Arguments and Flags:**
- `<function_name>`: Unique identifier for the function.
- `--<arg-key>=<arg-value>`: (Optional, repeatable) Argument key-value pairs passed to the function. These can have default values in the function definition, and may be overridden by the caller.

---

### EXEC

Execute a command in an ephemeral container. The command's `stdout` **must** emit a BuildKit-supported protobuf message describing the desired state.

**Syntax**
```
EXEC <command> [args...] [--timeout=<duration>]
```

**Arguments and Flags:**
- `<command>`: Command to execute in the ephemeral container.
- `--timeout=<duration>`: (Optional) Maximum execution duration. Defaults to `10m`. After timeout, the ephemeral container is removed.

---

## General Notes

- **Mixing Instructions**: Standard Dockerfile and Dexfile instructions may be freely mixed.
- **Ephemeral Containers**: Both `CTR` and `EXEC` operate on ephemeral containers created for their scope. These containers are removed after execution or timeout.
- **Context Awareness**: `PROC` instructions only make sense within a `CTR` block.
- **Conditional Branching**: `IF` blocks support both `ELSE IF` and `ELSE` branches for multi-path logic.
- **Looping**: `FOR` enables iteration over command output, with flexible splitting of results using `--delim`.
- **Functionality**: `FUNC` and `FUNC CALL` enable modular, reusable build logic with optional arguments and defaults.
- **Timeouts**: `EXEC`, `PROC`, `IF`, `ELSE`, and `FOR` support a `--timeout` flag (default: 10m). When timeout is reached, any ephemeral containers are removed.
- **Ignore Patterns**: Use `.dexnore` to optimize context and build performance. Patterns in `.dexnore` control which files/directories are excluded from the build context.

---

For further details and advanced usage, see the official Dexfile documentation or visit the [Dexfile repository](https://github.com/dexnore/dexfile).
