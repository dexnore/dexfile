package buildcontext

const (
	keyContextKeepGitDirArg = "build-arg:BUILDKIT_CONTEXT_KEEP_GIT_DIR"
)

const (
	KeyFilename      = "filename"
	KeyContextSubDir = "contextsubdir"
	KeyNameContext   = "contextkey"
	KeyNameDexfile   = "dexfilekey"
	KeyNameDockerfile = "dockerfilekey"
)

type sourceType string

const (
	SourceGit     sourceType = "GIT"
	SourceHTTP    sourceType = "HTTP"
	SourceImage   sourceType = "IMAGE"
	SourceInputs  sourceType = "INPUTS"
	SourceLocal   sourceType = "LOCAL"
	SourceOCI     sourceType = "OCI"
	SourceUnknown sourceType = ""
)
