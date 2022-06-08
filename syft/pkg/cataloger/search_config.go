package cataloger

import "github.com/anchore/syft/syft/source"

type SearchConfig struct {
	ByBuildTools             bool
	ByBuildToolsWithMode     string
	IncludeIndexedArchives   bool
	IncludeUnindexedArchives bool
	Scope                    source.Scope
}

func DefaultSearchConfig() SearchConfig {
	return SearchConfig{
		ByBuildTools:             false,
		ByBuildToolsWithMode:     "online",
		IncludeIndexedArchives:   true,
		IncludeUnindexedArchives: false,
		Scope:                    source.SquashedScope,
	}
}
