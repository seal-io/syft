/*
Package java provides a concrete Cataloger implementation for Java archives (jar, war, ear, par, sar, jpi, hpi formats).
*/
package java

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/anchore/syft/syft/source"
)

const (
	pomFilePattern    = "**/pom.xml"
	gradleFilePattern = "**/build.gradle"
)

// NewJavaCataloger returns a new Java archive cataloger object.
func NewJavaCataloger(src *source.Source, cfg Config) *common.GenericCataloger {
	// java build tool matching
	if cfg.SearchByBuildTools {
		var opts = scaffoldingParseOptions{
			mode:   cfg.SearchByBuildToolsWithMode,
			source: src,
		}
		rawGlobParsers := map[string]common.RawParserFn{
			pomFilePattern:    javaScaffoldingParserFn(mavenScaffolding, opts),
			gradleFilePattern: javaScaffoldingParserFn(gradleScaffolding, opts),
		}

		return common.NewGenericCatalogerWithPreciseLocation(nil, rawGlobParsers, "java-scaffolding-cataloger")
	}

	globParsers := make(map[string]common.ParserFn)

	// java archive formats
	for _, pattern := range archiveFormatGlobs {
		globParsers[pattern] = parseJavaArchive
	}

	if cfg.SearchIndexedArchives {
		// java archives wrapped within zip files
		for _, pattern := range genericZipGlobs {
			globParsers[pattern] = parseZipWrappedJavaArchive
		}
	}

	if cfg.SearchUnindexedArchives {
		// java archives wrapped within tar files
		for _, pattern := range genericTarGlobs {
			globParsers[pattern] = parseTarWrappedJavaArchive
		}
	}

	return common.NewGenericCataloger(nil, globParsers, "java-cataloger")
}
