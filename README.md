## Introduction

**Dexfile** is a BuildKit frontend built on top of **Dockerfile**. Every valid Dockerfile is also a valid Dexfile, but Dexfile extends the syntax with powerful new instructions for conditional logic, modularity, and advanced build workflows.

Like Docker, Dexfile allows you to define how images are built through a text-based file. It translates source code into build artifacts in an **efficient, expressive, and repeatable** way—ideal for modern CI/CD pipelines and platform operators.

### **Key features**:

* **Automatic garbage collection**

* **Concurrent dependency resolution**

* **Efficient instruction caching**

* **Build cache import/export**

* **Multiple output formats**

* **Execution without root privileges**

* **Integration for PaaS operators** – enabling one-click deploys

* **Simplified CI/CD** – replacing complex build scripts and config files

* **Selective rebuilds** – build only what changed to reduce time and costs

* **Improved reliability** – clearer separation of development vs. deployment

## Installation

Dexfile does not require a separate installation. It is distributed as a **BuildKit frontend**, so you only need to ensure your environment has one of the following:

### Option 1: Using Docker (recommended for most users)

* Install [Docker]().

* Ensure your [Docker version]() supports BuildKit (Docker 18.09+).

* Enable [BuildKit:]()

```bash
export DOCKER_BUILDKIT=1
```

Now, `docker build` can consume Dexfiles.

### Option 2: Using BuildKit directly (`buildctl`)

* Install [BuildKit.](https://github.com/moby/buildkit)

* [Start](https://github.com/moby/buildkit) the [BuildKit daemon](https://github.com/moby/buildkit) (either locally or via container):

  ```bash
  buildkitd
  ```

* Use `buildctl` to build with Dexfile:

  ```bash
  buildctl build \
    --frontend=gateway.v0 \
    --local context=. \
    --local dexfile=.
  ```

## Usage

To start using Dexfile in your project:

1. ### Add syntax directive

   At the top of your `Dexfile`, declare the Dexfile frontend:

   ```dockerfile
   # syntax=dexnore/dexfile:latest
   ```

   This will let the docker tools to interpret Dexfile content

2. ### Build an image from Dexfile

   With Docker:

   ```bash
   docker buildx build -f Dexfile -t myapp:latest .
   ```

   With BuildKit directly:

```bash
buildctl build \
  --frontend=gateway.v0 \
  --local context=. \
  --local dexfile=. \
  --output type=docker,name=myapp:latest
```

## [**.dexnore file**](https://docs.docker.com/reference/dockerfile/#dockerignore-file)

Place a `.dexnore` file in your project root to exclude unnecessary files from the build context (similar to `.dockerignore`):

```basic
node_modules
*.log
secrets/
```

## Instructions

Dexfile supports every dockerfile instruction and it’s flags until and unless specified explicitly. every Dockerfile is a valid Dexfile until it has valid syntax directive pointing to Dexfile image, but not vice versa.

Dexfile supports the following commands

| **Instruction**                                                                     | **Description**                                             |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| [`ADD`](https://docs.docker.com/reference/dockerfile/#add)                          | Add local or remote files and directories.                  |
| [`ARG`](https://docs.docker.com/reference/dockerfile/#arg)                          | Use build-time variables.                                   |
| [`CMD`](https://docs.docker.com/reference/dockerfile/#cmd)                          | Specify default commands.                                   |
| [`COPY`](https://docs.docker.com/reference/dockerfile/#copy)                        | Copy files and directories.                                 |
| [`ENTRYPOINT`](https://docs.docker.com/reference/dockerfile/#entrypoint)            | Specify default executable.                                 |
| [`ENV`](https://docs.docker.com/reference/dockerfile/#env)                          | Set environment variables.                                  |
| [`EXPOSE`](https://docs.docker.com/reference/dockerfile/#expose)                    | Describe which ports your application is listening on.      |
| [`FROM`](https://docs.docker.com/reference/dockerfile/#from)                        | Create a new build stage from a base image.                 |
| [`HEALTHCHECK`](https://docs.docker.com/reference/dockerfile/#healthcheck)          | Check a container's health on startup.                      |
| [`LABEL`](https://docs.docker.com/reference/dockerfile/#label)                      | Add metadata to an image.                                   |
| [`MAINTAINER`](https://docs.docker.com/reference/dockerfile/#maintainer-deprecated) | Specify the author of an image.                             |
| [`ONBUILD`](https://docs.docker.com/reference/dockerfile/#onbuild)                  | Specify instructions for when the image is used in a build. |
| [`RUN`](https://docs.docker.com/reference/dockerfile/#run)                          | Execute build commands.                                     |
| [`SHELL`](https://docs.docker.com/reference/dockerfile/#shell)                      | Set the default shell of an image.                          |
| [`STOPSIGNAL`](https://docs.docker.com/reference/dockerfile/#stopsignal)            | Specify the system call signal for exiting a container.     |
| [`USER`](https://docs.docker.com/reference/dockerfile/#user)                        | Set user and group ID.                                      |
| [`VOLUME`](https://docs.docker.com/reference/dockerfile/#volume)                    | Create volume mounts.                                       |
| [`WORKDIR`](https://docs.docker.com/reference/dockerfile/#workdir)                  | Change working directory.                                   |

In Addition Dexfile introduces the following new commands

| **Instruction**      | **Description**                                                                  |
| -------------------- | -------------------------------------------------------------------------------- |
| [`IF/ELSE`](./README.md#ifelse) | perform varying commands depending on the outcome of one or more conditions      |
| [`IMPORT`](./README.md#import)  | import external dockerfiles and dexfiles stages for reusability                  |
| [`FUNC`](./README.md#func)      | reusable block of instructions within the file                                   |
| [`FOR`](./README.md#for)        | loop over the set of result items                                                |
| [`CTR`](./README.md#ctr)        | creates an ephemeral container                                                   |
| [`PROC`](./README.md#proc)      | start a process in the ephemeral container                                       |
| [`BUILD`](./README.md#build)    | build the target stage from scratch and emit output                              |
| [`EXEC`](./README.md#exec)      | Incorporate the LLB result produced by EXEC into the active Dexfile build state. |

## IFELSE

The `IF` clause can perform varying commands depending on the outcome of one or more conditions. The expression passed as part of `<condition>` is evaluated by running it in the build environment. If the exit code of the expression is zero, then the block of that condition is executed. Otherwise, the control continues to the next `ELSE IF` condition (if any), or if no condition returns a non-zero exit code, the control continues to executing the `<else-block>`, if one is provided.

### Syntax

```dockerfile
IF [<condition-options>...] [ RUN | EXEC | PROC | BUILD ] <condition>
  <if-block>
ENDIF
```

```dockerfile
IF [<condition-options>...] [ RUN | EXEC | PROC | BUILD ] <condition>
  <if-block>
ELSE
  <else-block>
ENDIF
```

```dockerfile
IF [<condition-options>...] [ RUN | EXEC | PROC | BUILD ] <condition>
  <if-block>
ELSE IF [<condition-options>...] [ RUN | EXEC | PROC | BUILD ] <condition>
  <else-if-block>
...
ELSE
  <else-block>
ENDIF
```

> [!IMPORTANT] 
>
> Changes to the filesystem in expressions are not preserved. If a file is created as part of a `IF/ELSE` expression, then that file will not be present in the build environment for any subsequent commands.

A very common pattern is to use the POSIX shell `[ ... ]` conditions. For example the following marks port `8080` as exposed if the file `./foo` exists.

```dockerfile
IF RUN [ -f ./foo ]
  EXPOSE 8080
ENDIF
```

The `IF` or the `ELSE` conditions emit `STDOUT` and `STDERR` ARGs within the scope of the condition, which can be used to take farther actions

| **ARG**  | **Description**                      |
| -------- | ------------------------------------ |
| `STDOUT` | The standard output of the condition |
| `STDERR` | The standard error of the condition  |

```dockerfile
IF RUN echo "hello world!"
    RUN echo "${STDOUT}" # "hello world!"
ENDIF
```

### Options

| **FLAG**  | **Description**                      | **Default** |
| --------- | ------------------------------------ | ----------- |
| `timeout` | timeout for evaluating the condition | `10m`       |

`—timeout` flag is used to adjust the timeout of the condition. after exceeding the given timeout, the condition immediatly exits with error status code

```dockerfile
IF RUN sleep 900 && echo "hello world!" # this condition fails due to timeout
    RUN echo "succeed"
ELSE # this conditional block executes
    RUN echo "failed"
ENDIF
```

## IMPORT

The `IMPORT` instruction allows you to bring in stages from **external Dockerfiles or Dexfiles**. This enables **composability and reuse**, letting you split common build stages into separate files and reuse them across projects.

**This is particularly useful in:**

* **Monorepos** – share build logic across services.

* **Polyrepos** – reuse common base images or build stages.

* **Nested project structures** – import from deep subdirectories when needed.

### Syntax

```dockerfile
IMPORT [<import_options>...] <dexfile-ref> AS <alias>
```

* `<dexfile-ref>` defines the source (local, remote, Git, registry, etc.).

* `<alias>` names the imported stage so it can be referenced later.

### Supported Reference Types

| Type              | Example Usage                                                                                              | Description                                 |
| ----------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| `local:`          | `local:context`                                                                                            | Import from a local folder or file.         |
| `docker-image://` | `docker-image://ubuntu:22.04`                                                                              | Import from a Docker/OCI image.             |
| `oci-layout://`   | `oci-layout://images/app`                                                                                  | Import from an OCI image layout directory.  |
| `inputs:`         | `inputs:buildctx`                                                                                          | Import from a named BuildKit input context. |
| `git:`            | `git:`[`https://github.com/org/repo.git#main:docker`](https://github.com/org/repo.git#main:docker)         | Import from Git repo branch/tag/subdir.     |
| `https://`        | [`https://raw.githubusercontent.com/org/repo/Dexfile`](https://raw.githubusercontent.com/org/repo/Dexfile) | Import a Dexfile/Dockerfile over HTTP(S).   |

### Options

all the options are optional

| **FLAG**   | **Description**                                                                     | **type**          |
| ---------- | ----------------------------------------------------------------------------------- | ----------------- |
| `platform` | Target platform for the import. Defaults to current build platform.                 | `string`          |
| `target`   | Target stage to import (defaults to the last stage in the file).                    | `string`          |
| `file`     | Path to a Dexfile or Dockerfile (if omitted, `<dexfile-ref>` is treated as a blob). | `string`          |
| `opt`      | Build arguments (`KEY=VALUE`) passed to the imported stage. Can be repeated.        | array of `string` |

### Example

```dockerfile
IMPORT --platform=linux/arm64 \
    --target=release \
    --file=./Dexfile \
    --opt MY_ARG=value \
    local:context AS ctx
```

In this example:

* Import from the local context.

* Restrict to `linux/arm64` builds.

* Use the `release` stage from `./Dexfile`.

* Pass a custom build argument (`MY_ARG=value`).

* Alias the import as `ctx`.

## FUNC

The `FUNC` instruction defines a reusable function within a Dexfile. Functions allow you to group a set of instructions and reuse them across multiple stages, targets, or even within other functions.

In order to reference and execute a function, you may use the command `FUNC CALL`.

Unlike performing a `BUILD release`, functions inherit the build context and the build environment from the caller.

Functions create their own `ARG` scope, which is distinct from the caller. Any `ARG` that needs to be passed from the caller needs to be passed explicitly via `FUNC --<build-arg-key>=<build-arg-value> CALL release`.

### Syntax

```dockerfile
FUNC [ <build-arg-key>=<build-arg-value>... ] <func_name>
    <dexfile_commands>...
ENDFUNC
```

* `<func_name>` – the name of the function.

* `[<arg_key>=<arg_value>...]` – optional arguments defined for the function.

* `<dexfile_commands>` – the body of the function (any valid Dexfile instructions).

To invoke a function, use:

```dockerfile
FUNC [--<arg_key>=<arg_value>...] CALL <func_name>
```

### Example

Define a function:

```dockerfile
FUNC --greet="world" hello-world
    RUN echo "hello ${greet}!"
ENDFUNC
```

Call the function with a different argument:

```dockerfile
FUNC --greet="dexfile" CALL hello-world
# expands to: RUN echo "hello dexfile!"
```

### Key Points

* Functions promote **reusability** and **modularity** in Dexfiles.

* Caller and callee environments share the same build context.

* ARG values must be **explicitly passed** when calling a function.

* Functions can be nested or composed inside other functions for advanced workflows.

## FOR

The `FOR` clause iterates over the items resulting from an expression (`<expression>`). On each iteration, the value of `<variable-name>` is set to the current item, and the block of commands (`<for-block>`) is executed in the context of that variable, which is available as a build argument.

> [!IMPORTANT] 
>
> Changes to the filesystem in expressions are not preserved. If a file is created as part of a `FOR` expression, then that file will not be present in the build environment for any subsequent commands.

| **ARG**          | **Description**                |
| ---------------- | ------------------------------ |
| `INDEX`          | Current index of the iteration |
| `<vaiable-name>` | Value of the current item      |

### Syntax

```dockerfile
FOR [<options>...] <variable-name> IN [ RUN | EXEC | PROC ] <expression>
  <for-block>
ENDFOR
```

### Options

| **FLAG**       | **Description**                                                             | **Default** |
| -------------- | --------------------------------------------------------------------------- | ----------- |
| `regex`        | Regex compiled against the expression output to generate the variable value | `\n`        |
| `regex-action` | How to interpret the regex against the output (`split` or `match`)          | `split`     |
| `timeout`      | Timeout for evaluating the expression                                       | `10m`       |

### Examples

```dockerfile
FOR file IN RUN ls
  RUN gcc "${file}" -o "${file}.o" -c
END
```

**Explanation:**

* The `RUN ls` expression lists all files in the current directory.

* Each result is assigned to the variable `file`.

* On each iteration, `gcc` compiles that file into an object file (`.o`).

* After the loop completes, every file in the directory has been compiled.

## CTR

The `CTR` clause is used to create an **ephemeral container**. All containers created with `CTR` are automatically cleaned up once the block reaches `ENDCTR`. Processes inside the container can be executed using the `PROC` instruction.

A `CTR` block can supports all instructions and take effect on current stage, except `PROC`.

**Key Points:**

* No image layers are committed from a `CTR` block.

* Use `PROC` inside `CTR` for isolated operations.

* Ideal for testing, building, or ephemeral operations that should not persist in the final image.

### Syntax

```dockerfile
CTR [<ctr_options>...] <ctr_name> [ FROM <base_image_name> ]
    <ctr-block>...
ENDCTR
```

* If `FROM <base_image_name>` is omitted, the container defaults to the **current state of the stage**.

* The `<ctr_name>` can be referenced by `PROC` to execute processes,[ eve]()n when nested `CTR` blocks are used.

### Options

| **FLAG** | **Description**                                                 |
| -------- | --------------------------------------------------------------- |
| `mount`  | Create filesystem mounts accessible by the ephemeral container. |

### Examples

```dockerfile
CTR tester
    PROC npx jest # run inside ephemeral container
    RUN npx jest # run as part of the build state
ENDCTR
```

## PROC

The **PROC** instruction starts a process inside an **ephemeral container** created by `CTR`.\
Any filesystem changes made by this process are **discarded** when the container exits.\
This makes it ideal for **testing or running commands without persisting changes**.

### STDOUT & STDERR

Each `PROC` emits two ARGs: `STDOUT` and `STDERR`.\
These can be referenced by subsequent instructions to trigger additional actions.

| **ARG**  | **Description**                               |
| -------- | --------------------------------------------- |
| `STDOUT` | Standard output of the executed process       |
| `STDERR` | Standard error output of the executed process |

### Syntax

```dockerfile
PROC [ <proc_options>... ] <expression>
```

### Options

| **FLAG**  | **Description**                                 | **Default**       |
| --------- | ----------------------------------------------- | ----------------- |
| `from`    | Target container name to execute the process in | current container |
| `timeout` | Timeout for process execution                   | `10m`             |

### Example

```dockerfile
CTR hello-world
    CTR hello-dexfile
        # execute process in `hello-dexfile` container
        PROC echo "hello dexfile!"
        # execute process in `hello-world` container
        PROC --from="hello-world" echo "hello world!"
    ENDCTR
ENDCTR
```

## BUILD

The **BUILD** instruction triggers Dexfile to **invoke the build of a target stage** referenced by `<target-ref>`.

Once a `BUILD` command is reached, **no further instructions** in the current stage are executed.

Unlike multi-stage `COPY --from=...`, the `BUILD` instruction **rebuilds** the referenced target **from scratch**, ignoring any prior build state or caching of that target. This ensures deterministic and isolated builds.

### Syntax

```dockerfile
BUILD [ <build-arg-key>=<build-arg-value>... ] <target-ref>
```

* `<target-ref>`: The name of the stage or target to build.

* `<build-arg-key>=<build-arg-value>`: Optional build arguments to pass into the referenced target.

### Options

| **FLAG**                            | **Description**                                                              |
| ----------------------------------- | ---------------------------------------------------------------------------- |
| `<build-arg-key>=<build-arg-value>` | Array of key-value pairs passed as build-time arguments for the target stage |

### Key Points

* A `BUILD` always starts the referenced target from **scratch**.

* The current stage **stops execution** after a `BUILD`.

* Useful for **composing multiple targets** or chaining dependent builds.

* Acts like calling another stage’s build as a subroutine.

### Examples

```dockerfile
FROM alpine:latest as hello-world
RUN echo "hello world!"

FROM scratch
# Build the hello-world target from scratch
BUILD hello-world
```

In this example:

* The first stage (`hello-world`) prints a message.

* The second stage (`scratch`) invokes `BUILD hello-world`, rebuilding it independently.

## EXEC

The **EXEC** instruction is used for **advanced scenarios** where Dexfile’s built-in instructions are insufficient.

It executes an external command, expecting its **stdout to emit BuildKit LLB (Low-Level Build) state in Protobuf format**.

The emitted LLB is then **merged into the current build state**, effectively extending the build graph dynamically.

### Syntax

```dockerfile
EXEC [ <run_options>... ] <expression>
```

* `<expression>`: The command or binary to execute.

* The command’s stdout **must** output a valid BuildKit LLB definition.

### Options

The `EXEC` instruction supports `mount` `network` `security` flags supported by `RUN` instruction.

### Examples

```dockerfile
FROM mycustomimage:latest
# print-proto executable stdout's the buildkit supported llb state
EXEC print-proto
```

### Key Points

* `EXEC` allows **custom integration** of external tools with BuildKit.

* The emitted LLB is **merged into the current build state**.

* If the command fails or emits invalid LLB, the build fails.

## Meta Stage

The meta stage is a lightweight, implicit initialization stage that runs before any standard build stages. Its purpose is to centralize global configuration, environment setup, and reusable build arguments, providing a deterministic foundation for all subsequent stages.

### Core Principles

1. Implicit Stage
    * Any Dexfile instruction before the first `FROM` is automatically part of the meta stage.
    * No explicit declaration is required; Dexfile recognizes these instructions and executes them in isolation.
2. Base Image
    * The meta stage always uses `busybox:latest` as its base image.
    * This keeps it lightweight and ensures deterministic behavior.
3. Global Arguments
    * All `ARG` and `ENV` instructions defined in the meta stage become **meta arguments**.
    * Meta arguments are globally accessible to all subsequent stages, allowing consistent configuration.
4. Isolation and Determinism
    * All filesystem changes and instructions in the meta stage are confined to that stage.
    * Changes are only propagated to later stages if explicitly referenced via COPY --from=meta or similar mechanisms.

### Example
```Dockerfile
ARG VERSION=1.6.1
IF RUN [ -z "${VERSION}" ]
  RUN echo "VERSION is required" >&2 && exit 1
ENDIF

FROM alpine:$VERSION
```
