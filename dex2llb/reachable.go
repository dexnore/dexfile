package dex2llb

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/containerd/platforms"
	"github.com/dexnore/dexfile"
	config "github.com/dexnore/dexfile/client/config"
	"github.com/dexnore/dexfile/context/buildcontext"
	dexcontext "github.com/dexnore/dexfile/context/dexfile"
	"github.com/dexnore/dexfile/instructions/converter"
	"github.com/dexnore/dexfile/instructions/parser"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/util/suggest"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

type namedContext func(name string, copt dexfile.ContextOpt) (dexfile.NamedContext, error)
type stageResolver struct {
	allDispatchStates *dispatchStates
	namedContext namedContext
	platformOpt *platformOpt
	metaResolver llb.ImageMetaResolver
	lint *linter.Linter
	opt dexfile.ConvertOpt
}

type rechableStageResolver interface {
	resolve(ctx context.Context, all []*dispatchState, target *dispatchState) (map[*dispatchState]struct{}, error)
}

func (s *stageResolver) resolve (ctx context.Context, all []*dispatchState, target *dispatchState) (map[*dispatchState]struct{}, error) {
	allReachable := allReachableStages(target)
	eg, ctx := errgroup.WithContext(ctx)
	for i, d := range all {
		_, reachable := allReachable[d]
		if s.opt.AllStages {
			reachable = true
		}
		// resolve image config for every stage
		if d.base == nil && !d.dispatched && !d.resolved {
			d.resolved = reachable // avoid re-resolving if called again after onbuild
			if d.BaseName() == dexfile.EmptyImageName && d.namedContext == nil {
				d.state = llb.Scratch()
				d.image = emptyImage(s.platformOpt.targetPlatform)
				d.platform = &s.platformOpt.targetPlatform
				if d.unregistered {
					d.dispatched = true
				}
				continue
			}

			func(i int, d *dispatchState) {
				eg.Go(func() (err error) {
					defer func() {
						if err != nil {
							err = parser.WithLocation(err, d.Location())
						}
						if d.unregistered {
							// implicit stages don't need further dispatch
							d.dispatched = true
						}
					}()
					origName := d.BaseName()
					var ref reference.Named
					if d.stage.BaseName != "" {
						ref, err = reference.ParseNormalizedNamed(d.BaseName())
						if err != nil {
							return errors.Wrapf(err, "failed to parse stage name %q", origName)
						}
						d.SetBaseName(reference.TagNameOnly(ref).String())
					}
					platform := d.platform
					if platform == nil {
						platform = &s.platformOpt.targetPlatform
					}
					var isScratch bool
					if reachable {
						isStage := d.stage.BaseName != ""
						// stage was named context
						if d.namedContext != nil {
							st, img, err := d.namedContext.Load(ctx)
							if err != nil {
								return err
							}
							d.dispatched = true
							d.state = *st
							if img != nil {
								// timestamps are inherited as-is, regardless to SOURCE_DATE_EPOCH
								// https://github.com/moby/buildkit/issues/4614
								d.image = *img
								if img.Architecture != "" && img.OS != "" {
									d.platform = &ocispecs.Platform{
										OS:           img.OS,
										Architecture: img.Architecture,
										Variant:      img.Variant,
										OSVersion:    img.OSVersion,
									}
									if img.OSFeatures != nil {
										d.platform.OSFeatures = slices.Clone(img.OSFeatures)
									}
								}
							}

							if !isStage && d.imports.FileName != "" {
								filenames := []string{d.imports.FileName, d.imports.FileName + dexfile.DefaultDexnoreName}

								// dockerfile is also supported casing moby/moby#10858
								if path.Base(d.imports.FileName) == dexfile.DefaultDexfileName {
									filenames = append(filenames, path.Join(path.Dir(d.imports.FileName), strings.ToLower(dexfile.DefaultDexfileName)))
								}

								bc, err := s.opt.BC.BuildContext(ctx)
								if err != nil {
									return err
								}
								bc.Context = &d.state
								bc.Dexfile = &d.state
								bc.Filename = d.imports.FileName
								dfile := dexcontext.New(s.opt.Client, bc)
								src, err := dfile.Dexfile(ctx, dexfile.DefaultDexfileName, llb.FollowPaths(filenames))
								if err != nil {
									return err
								}

								bc.Dexfile = src.Sources().State

								c := s.opt.Client.Clone()
								c.DelOpt("cmdline")
								c.DelOpt("source")
								c.DelOpt("build-arg:BUILDKIT_SYNTAX")
								c.SetOpt(buildcontext.KeyFilename, d.imports.FileName)
								c.SetOpt(config.KeyTarget, d.imports.Target)
								for _, v := range d.imports.Options {
									c.SetOpt(v.Key, v.ValueString())
								}
								if err = c.InitConfig(); err != nil {
									return err
								}
								slver, err := s.opt.Solver.With(c, bc, false)
								if err != nil {
									return err
								}

								res, err := slver.Solve(ctx)
								if err != nil {
									return err
								}

								pt := platforms.FormatAll(*platform)
								ref, ok := res.FindRef(pt)
								if !ok {
									return errors.Errorf("no import found with platform %s", pt)
								}

								d.state, err = ref.ToState()
								if err != nil {
									return err
								}

								imgBytes := res.Metadata[fmt.Sprintf("%s/%s", exptypes.ExporterImageConfigKey, pt)]
								if len(imgBytes) == 0 {
									imgBytes = res.Metadata[exptypes.ExporterImageConfigKey]
								}

								var img *dockerspec.DockerOCIImage
								if err := json.Unmarshal(imgBytes, img); err != nil {
									i := emptyImage(*platform)
									img = &i
								}
								d.image = *img

								var baseImg *dockerspec.DockerOCIImage
								baseImgBytes := res.Metadata[fmt.Sprintf("%s/%s", exptypes.ExporterImageBaseConfigKey, pt)]
								if len(baseImgBytes) == 0 {
									baseImgBytes = res.Metadata[exptypes.ExporterImageBaseConfigKey]
								}
								if err := json.Unmarshal(baseImgBytes, baseImg); err != nil {
									img = new(dockerspec.DockerOCIImage) // avoid nil pointer
									*img = emptyImage(*platform)
								}
								d.baseImg = baseImg

								d.platform = platform
								return nil
							}
							return nil
						}
						if isStage {
							// check if base is named context
							nc, err := s.namedContext(d.BaseName(), dexfile.ContextOpt{
								ResolveMode:    s.opt.Config.ImageResolveMode.String(),
								Platform:       platform,
								AsyncLocalOpts: d.asyncLocalOpts,
							})
							if err != nil {
								return err
							}
							if nc != nil {
								st, img, err := nc.Load(ctx)
								if err != nil {
									return err
								}
								if st == nil {
									return errors.Errorf("named context %q did not return a valid state", d.BaseName())
								}
								if img != nil {
									d.image = *img
								} else {
									d.image = emptyImage(s.platformOpt.targetPlatform)
								}
								d.state = st.Platform(*platform)
								d.platform = platform
								return nil
							}
							prefix := "["
							if s.opt.Config.MultiPlatformRequested && platform != nil {
								prefix += platforms.FormatAll(*platform) + " "
							}
							prefix += "internal]"
							mutRef, dgst, dt, err := s.metaResolver.ResolveImageConfig(ctx, d.BaseName(), sourceresolver.Opt{
								LogName:  fmt.Sprintf("%s load metadata for %s", prefix, d.BaseName()),
								Platform: platform,
								ImageOpt: &sourceresolver.ResolveImageOpt{
									ResolveMode: s.opt.Config.ImageResolveMode.String(),
								},
							})
							if err != nil {
								return suggest.WrapError(errors.Wrap(err, origName), origName, append(s.allDispatchStates.names(), commonImageNames()...), true)
							}

							if ref.String() != mutRef {
								ref, err = reference.ParseNormalizedNamed(mutRef)
								if err != nil {
									return errors.Wrapf(err, "failed to parse ref %q", mutRef)
								}
							}
							var img dockerspec.DockerOCIImage
							if err := json.Unmarshal(dt, &img); err != nil {
								return errors.Wrap(err, "failed to parse image config")
							}
							d.baseImg = cloneX(&img) // immutable
							img.Created = nil
							// if there is no explicit target platform, try to match based on image config
							if d.platform == nil && s.platformOpt.implicitTarget {
								p := autoDetectPlatform(img, *platform, s.platformOpt.buildPlatforms)
								platform = &p
							}
							if dgst != "" {
								ref, err = reference.WithDigest(ref, dgst)
								if err != nil {
									return err
								}
							}
							d.SetBaseName(ref.String())
							if len(img.RootFS.DiffIDs) == 0 {
								isScratch = true
								// schema1 images can't return diffIDs so double check :(
								for _, h := range img.History {
									if !h.EmptyLayer {
										isScratch = false
										break
									}
								}
							}
							d.image = img
						}
					}
					if isScratch {
						d.state = llb.Scratch()
					} else {
						d.state = llb.Image(d.BaseName(),
							dfCmd(d.SourceCode()),
							llb.Platform(*platform),
							s.opt.Config.ImageResolveMode,
							llb.WithCustomName(prefixCommand(d, "FROM "+d.BaseName(), s.opt.Config.MultiPlatformRequested, platform, emptyEnvs{})),
							location(s.opt.SourceMap, d.Location()),
						)
						if reachable {
							validateBaseImagePlatform(origName, *platform, d.image.Platform, d.Location(), s.lint)
						}
					}
					d.platform = platform
					return nil
				})
			}(i, d)
		}
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return allReachable, nil
}

func (s *stageResolver) Clone() *stageResolver {
	return &stageResolver{
		allDispatchStates: s.allDispatchStates,
		namedContext:      s.namedContext,
		platformOpt:       s.platformOpt,
		metaResolver:      s.metaResolver,
		lint:              s.lint,
	}
}

func resolveReachableStage(ctx context.Context, allDispatchStates *dispatchStates, target *dispatchState, resolveReachableStages rechableStageResolver) (allReachable map[*dispatchState]struct{}, err error) {
	if resolveReachableStages == nil {
		return nil, errors.Errorf("unable to resolve stage: %q", target.stageName)
	}
	for {
		allReachable, err = resolveReachableStages.resolve(ctx, allDispatchStates.states, target)
		if err != nil {
			return nil, err
		}

		// initialize onbuild triggers in case they create new dependencies
		newDeps := false
		for d := range allReachable {
			d.init()
			
			onbuilds := slices.Clone(d.image.Config.OnBuild)
			if d.base != nil && !d.onBuildInit {
				for _, cmd := range d.base.commands {
					if obCmd, ok := cmd.Command.(*converter.OnbuildCommand); ok {
						onbuilds = append(onbuilds, obCmd.Expression)
					}
				}
				d.onBuildInit = true
			}

			if len(onbuilds) > 0 {
				if b, err := initOnBuildTriggers(d, onbuilds, allDispatchStates); err != nil {
					return nil, parser.SetLocation(err, d.Location())
				} else if b {
					newDeps = true
				}
				d.image.Config.OnBuild = nil
			}
		}
		// in case new dependencies were added, we need to re-resolve reachable stages
		if !newDeps {
			break
		}
	}
	return allReachable, err
}
