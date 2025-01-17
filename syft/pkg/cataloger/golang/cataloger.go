/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewGoModFileCataloger returns a new Go module cataloger object.
func NewGoModFileCataloger(cfg Config) *generic.Cataloger {
	if cfg.SearchByBuildTools && cfg.SearchByBuildToolsWithMode == "online" {
		return generic.NewCataloger("go-mod-scaffolding-cataloger").
			WithParserByGlobs(scaffoldingParser(), "**/go.mod")
	}

	return generic.NewCataloger("go-mod-file-cataloger").
		WithParserByGlobs(parseGoModFile, "**/go.mod")
}

// NewGoModuleBinaryCataloger returns a new Golang cataloger object.
func NewGoModuleBinaryCataloger() *generic.Cataloger {
	return generic.NewCataloger("go-module-binary-cataloger").
		WithParserByMimeTypes(parseGoBinary, internal.ExecutableMIMETypeSet.List()...)
}
