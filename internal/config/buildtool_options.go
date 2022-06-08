package config

import (
	"fmt"
	"github.com/spf13/viper"
)

type buildtoolsOptions struct {
	Enabled bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Mode    string `yaml:"mode" json:"mode" mapstructure:"mode"`
}

func (cfg buildtoolsOptions) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("package.search-by-buildtools.enabled", false)
	v.SetDefault("package.search-by-buildtools.mode", "online")
}

func (cfg *buildtoolsOptions) parseConfigValues() error {
	if cfg.Enabled {
		switch cfg.Mode {
		default:
			return fmt.Errorf("unknown build tools search mode: %s", cfg.Mode)
		case "":
			cfg.Mode = "online"
		case "online", "offline":
		}
	}
	return nil
}
