package cataloger

import (
	"github.com/anchore/syft/syft/pkg/cataloger/java"
)

type Config struct {
	Search SearchConfig
}

func DefaultConfig() Config {
	return Config{
		Search: DefaultSearchConfig(),
	}
}

func (c Config) Java() java.Config {
	return java.Config{
		SearchByBuildTools:         c.Search.ByBuildTools,
		SearchByBuildToolsWithMode: c.Search.ByBuildToolsWithMode,
		SearchUnindexedArchives:    c.Search.IncludeUnindexedArchives,
		SearchIndexedArchives:      c.Search.IncludeIndexedArchives,
	}
}
