package java

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/anchore/syft/syft/source"
)

type scaffolding uint8

const (
	mavenScaffolding scaffolding = iota + 1
	gradleScaffolding
)

type scaffoldingParseOptions struct {
	mode string
}

func javaScaffoldingParserFn(in scaffolding, opts scaffoldingParseOptions) common.RawParserFn {
	return func(loc source.Location, r io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
		return parseScaffolding(in, loc, r, opts)
	}
}

func parseScaffolding(target scaffolding, location source.Location, reader io.Reader, options scaffoldingParseOptions) ([]*pkg.Package, []artifact.Relationship, error) {
	var ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var (
		currentFilepath  = string(location.VisibleRealPath())
		relativeFilePath = location.Coordinates.RealPath
		mode             = options.mode
		pkgs             []*pkg.Package
		relationships    []artifact.Relationship
		err              error
	)
	switch target {
	default:
		return nil, nil, errors.New("unknown scaffolding")
	case mavenScaffolding:
		if strings.Contains(currentFilepath, "/target/META-INF/") {
			// temporary build directory
			return nil, nil, nil
		}

		mavenParser := newMavenScaffoldingParser(mode, currentFilepath, relativeFilePath, reader)
		pkgs, relationships, err = mavenParser.parse(ctx)
		if err != nil {
			return nil, nil, err
		}
	case gradleScaffolding:
		gradleParser := newGradleScaffoldingParser(mode, currentFilepath)
		pkgs, relationships, err = gradleParser.parse(ctx)
		if err != nil {
			return nil, nil, err
		}
	}

	for _, pg := range pkgs {
		addPURL(pg)
	}

	return pkgs, relationships, nil
}

func newCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	var binPath, err = exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s is required for runtime: %w", name, err)
	}
	var cmd = exec.CommandContext(ctx, binPath, args...)
	return cmd, nil
}

func toPackage(groupID, artifactID, version, virtualPath string, isRoot bool, mainProject *pkg.PomProject) *pkg.Package {
	pomProperties := &pkg.PomProperties{
		GroupID:    groupID,
		ArtifactID: artifactID,
		Version:    version,
		Name:       artifactID,
	}

	return &pkg.Package{
		Name:         pomProperties.ArtifactID,
		Version:      pomProperties.Version,
		Language:     pkg.Java,
		Type:         pomProperties.PkgTypeIndicated(),
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			PomProject:    mainProject,
			IsRootPackage: isRoot,
			VirtualPath:   virtualPath,
			PomProperties: pomProperties,
		},
	}
}
