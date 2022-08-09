package java

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

type PackageURL struct {
	pkg.Package
}

func (p *PackageURL) ID() artifact.ID {
	return artifact.ID(packageURL(p.Package))
}
