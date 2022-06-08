package golang

import (
	"fmt"
	"strings"
)

type Module struct {
	ModuleInfo
	Main    bool        `json:"Main,omitempty"`
	Replace *ModuleInfo `json:"Replace,omitempty"`
}

type ModuleInfo struct {
	Version   string `json:"Version,omitempty"`
	Path      string `json:"Path,omitempty"`
	GoMod     string `json:"GoMod,omitempty"`
	GoVersion string `json:"GoVersion,omitempty"`
}

func (m *Module) String() string {
	if m.Version == "" {
		return m.Path
	}
	return fmt.Sprintf("%s@%s", m.Path, m.Version)
}

func findModule(modules []*Module, query string, strict bool) *Module {
	for i := range modules {
		if query == modules[i].String() || (!strict && strings.HasPrefix(query, modules[i].Path+"@")) {
			return modules[i]
		}
	}
	return nil
}
