# Dexfile Reference
Welcome to the Dexfile Reference documentation. This document provides a detailed guide to the instructions available in a Dexfile, designed for building and managing complex software build workflows. Dexfiles offer a powerful and flexible way to define build processes with features like conditional logic, containerized execution contexts, and reusable functions.

## IMPORT
The IMPORT instruction is used to bring in external resources into your build process. These can be other Dexfiles, container images, or build contexts from various sources like local paths, Git repositories, or OCI registries. This allows for creating modular and composable build definitions.
```Syntax
IMPORT [flags] <source> AS <alias>
```
 - `<source>`: The URI of the resource to import. Supported schemes include:
    - `local:<path>`: A local directory.
    - `docker-image://<image>:<tag>`: A Docker image from a registry.
    - `oci-layout://<path>`: An OCI image layout on the local filesystem.
    - `inputs:<name>`: A frontend-specific input.
    - `git:<url>`: A Git repository.
    - `https://<url>`: An HTTP(S) URL pointing to a context.
  - `<alias>`: A name to refer to the imported resource within the Dexfile.
  - `--file=<path>`: (Optional) Specifies the path to a Dexfile within the source context. If omitted, the basename of the source is used as the build context.
### Examples
#### Importing a local Dexfile:
This example imports a `Dexfile` from a local directory named `shared-builds` and aliases it as common.
```Syntax
IMPORT --file=common.dex local:shared-builds AS common
```
#### Importing a Docker Image:
Here, we import the official `node:18-alpine` image to use as a base for a containerized step.
```Syntax
IMPORT docker-image://node:18-alpine AS node-base
```
#### Importing from a Git Repository:
This imports a build context directly from a GitHub repository.
```Syntax
IMPORT --file=build.dex git:https://github.com/my-org/my-project AS project-from-git
```
## `CTR / ENDCTR`
The CTR block defines a scope where instructions are executed inside a specified container. This is useful for creating isolated build environments or running tasks that require specific tooling not available in the main build stage.
```Syntax
CTR --from=<image_alias>
    <instructions>...
ENDCTR
```
  - `--from=<image_alias>`: Specifies the container image to use for this block. The image must be previously imported using the IMPORT instruction.
### Details
Instructions within a `CTR` block, such as `PROC`, operate inside the container's filesystem and environment. Other instructions like `RUN` will execute on the current stage, not inside the container, unless they are part of a `PROC` command.This provides a powerful way to separate build-time dependencies from the final runtime environment.
### Example
This example uses a golang container to compile a Go application. The source code is copied into the container, built, and the resulting binary can then be used in a later stage.
```Syntax
IMPORT docker-image://golang:1.20 AS go-builder

CTR --from=go-builder
    # Set the working directory inside the container
    WORKDIR /app

    # Copy source code into the container (assuming a COPY instruction exists)
    COPY . .

    # Run the build process inside the container
    PROC go build -o /app/my-app .
ENDCTR
```
## PROC
The `PROC` instruction executes a command as a process inside the container defined by a `CTR` block. It is the primary way to run commands within the containerized environment. `PROC` can only be used within a `CTR/ENDCTR` block.
```Syntax
PROC <command>
```
  - `<command>`: The command and its arguments to execute inside the container.
#### Example
In this example, we use a python container to install dependencies from a requirements.txt file.
```Syntax
IMPORT docker-image://python:3.10-slim AS python-env

CTR --from=python-env
    WORKDIR /app
    COPY requirements.txt .

    # Install Python dependencies inside the container
    PROC pip install --no-cache-dir -r requirements.txt
ENDCTR
```

## `IF / ELSE / ENDIF`
The IF block allows for conditional execution of instructions based on the outcome of a command. This enables dynamic build workflows that can adapt to different conditions, such as the presence of certain files or the output of a script.
```Syntax
IF [RUN | EXEC | PROC] <command>
    <if_instructions>...
[ELSE | ELSE IF [RUN | EXEC | PROC] <command>]
    <else_instructions>...
ENDIF
```
The condition is determined by the exit code of the `<command>`. A zero exit code is considered true, and a non-zero exit code is considered false.RUN, EXEC, or PROC can be used to execute the conditional command. PROC is only valid within a CTR block.The environment variables `STDOUT` and `STDERR` are available within the IF/ELSE blocks, containing the output of the conditional command.
### Example: 
Detecting Project TypeThis example demonstrates how to detect if a project is a Node.js or Python project and then run the appropriate dependency installation command.
```Syntax
# Assume this CTR block is for a general-purpose environment with both node and python
CTR --from=my-polyglot-image
    WORKDIR /src
    COPY . .

    # Check if a package.json file exists
    IF RUN test -f package.json
        # It's a Node.js project
        RUN echo "Node.js project detected. Installing dependencies."
        PROC npm install
    ELSE IF RUN test -f requirements.txt
        # It's a Python project
        RUN echo "Python project detected. Installing dependencies."
        PROC pip install -r requirements.txt
    ELSE
        # Neither was found
        RUN echo "Could not determine project type. No dependencies installed."
    ENDIF
ENDCTR
```
## `FUNC / ENDFUNC / CALL`
The FUNC instruction allows you to define reusable groups of instructions. These functions can then be invoked later in the Dexfile using the CALL instruction, promoting modularity and reducing duplication.
```Syntax
# Definition:
FUNC <function_name>
    <instructions>...
ENDFUNC
# Invocation:
FUNC CALL <function_name>
```
  - `<function_name>`: A unique name for the function.
### Example: 
Reusable Build and Test FunctionThis example defines a function to build and test a generic application, then calls it for different components.
```Syntax
# Define a reusable function to build and test
FUNC build_and_test
    RUN echo "Starting build..."
    PROC make build
    RUN echo "Running tests..."
    PROC make test
ENDFUNC

# --- Main Build Logic ---

# Build the backend service
CTR --from=go-builder
    WORKDIR /app/backend
    COPY ./backend .
    FUNC CALL build_and_test
ENDCTR

# Build the frontend service
CTR --from=node-builder
    WORKDIR /app/frontend
    COPY ./frontend .
    FUNC CALL build_and_test
ENDCTR
```
## `EXEC`
The EXEC instruction is an advanced feature for extending Dexfile's capabilities. It executes a command on the build host that is expected to output a pb.Definition protobuf message to its standard output. This allows for the dynamic generation of build steps and the creation of custom high-level instructions.
```Syntax
EXEC <command>
```
  - `<command>`: A command that, when executed, prints a valid pb.Definition to stdout.Use CaseEXEC is intended for complex scenarios where the standard Dexfile instructions are insufficient. For example, you could write a script that inspects a project's structure and generates a tailored set of CTR and PROC instructions based on the services it finds.ExampleImagine a script generate-build-steps.sh that analyzes a monorepo and generates build steps.
```Syntax
# generate-build-steps.sh
#!/bin/bash
# This script would contain logic to generate a pb.Definition
# For demonstration, it just prints a pre-defined protobuf definition
cat <<EOF
... a valid pb.Definition protobuf message ...
EOF
```
In the Dexfile, you would use it like this:
```Syntax
# Dynamically generate and execute build steps based on the project structure
EXEC ./scripts/generate-build-steps.sh
```
