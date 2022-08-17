/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/anchore/syft/syft/source"
)

const (
	goFilePattern           = "**/go.mod"
	goModFileCatalog        = "go-mod-file-cataloger"
	goModScaffoldingCatalog = "go-mod-scaffolding-cataloger"
)

// NewGoModFileCataloger returns a new Go module cataloger object.
func NewGoModFileCataloger(src *source.Source, cfg Config) *common.GenericCataloger {
	if cfg.Mode == "online" && cfg.SearchByBuildTools {
		globParsers := map[string]common.RawParserFn{
			goFilePattern: scaffoldingParserFn(src),
		}
		return common.NewGenericCatalogerWithPreciseLocation(nil, globParsers, goModScaffoldingCatalog)
	}

	globParsers := map[string]common.ParserFn{
		goFilePattern: parseGoMod,
	}
	return common.NewGenericCataloger(nil, globParsers, goModFileCatalog)
}
