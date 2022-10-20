package cataloger

import (
	"context"
	"time"

	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
)

type Version interface {
	Init(ctx context.Context, workspace, registry string) error
	ListAvailableVersions(ctx context.Context, depName string) ([]string, error)
	GetDependencyFilePattern() string
	GetPackageManager() string
	GetLanguage() string
	GetReleaseTime(ctx context.Context, depName string, versions ...string) (map[string]time.Time, error)
	IsPreRelease(ctx context.Context, version string) (bool, error)
	IsBreakingChange(newVersion, oldVersion string) (bool, error)
	IsDirectDependency(ctx context.Context, depName string) (bool, error)
	// Compare compares this version to another one. It returns -1, 0, or 1 if
	// the version smaller, equal, or larger than the other version.
	Compare(newVersion, oldVersion string) (int, error)
	// Sort sorts version in ascending order
	Sort(versions []string) error
	AddDependency(ctx context.Context, depName, version string) error
	UpdateDependencyFile(ctx context.Context) error
	FindConflicts(ctx context.Context) (map[string][][]string, error)
}

func Versions() []Version {
	return []Version{
		golang.New(),
		java.NewMaven(),
	}
}
