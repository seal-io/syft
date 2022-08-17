package java

import (
	"context"
	"errors"
	"io"
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
	mode   string
	source *source.Source
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

		mavenParser := newMavenScaffoldingParser(mode, currentFilepath, relativeFilePath, reader, options.source)
		pkgs, relationships, err = mavenParser.parse(ctx)
		if err != nil {
			return nil, nil, err
		}
	case gradleScaffolding:
		gradleParser := newGradleScaffoldingParser(mode, currentFilepath, relativeFilePath, options.source)
		pkgs, relationships, err = gradleParser.parse(ctx)
		if err != nil {
			return nil, nil, err
		}
	}

	return pkgs, relationships, nil
}

func toPackage(groupID, artifactID, version string, curProj *pkg.PomProject) *pkg.Package {
	pomProperties := &pkg.PomProperties{
		GroupID:    groupID,
		ArtifactID: artifactID,
		Version:    version,
		Name:       artifactID,
	}

	p := &pkg.Package{
		Name:         pomProperties.ArtifactID,
		Version:      pomProperties.Version,
		Language:     pkg.Java,
		Type:         pomProperties.PkgTypeIndicated(),
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			PomProject:    curProj,
			PomProperties: pomProperties,
		},
	}
	addPURL(p)
	p.SetID()
	return p
}

func toRelation(from, to *pkg.Package) *artifact.Relationship {
	return &artifact.Relationship{
		From: from,
		To:   to,
		Type: artifact.DependencyOfRelationship,
	}
}
