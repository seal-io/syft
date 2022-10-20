package golang

import (
	"bufio"
	"context"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

func New() *Version {
	return &Version{
		dependencyFilePattern: goFilePattern,
	}
}

type Version struct {
	workspaceDir          string
	dependencyFilePattern string
	runner                *commandRunner
	modules               map[string]*pkg.Module
}

type node struct {
	depNameWithVersion string // dependency name with version
	child              []*node
	dependencyTrails   []string
}

// Init set the workspace for running command
func (v *Version) Init(ctx context.Context, workspace, registry string) error {
	v.workspaceDir = workspace
	v.runner = newRunner(workspace)
	// TODO(michelia): set registry after implementing go registry

	// init with go modules
	modules, err := v.runner.listAllModules(ctx)
	if err != nil {
		return err
	}
	v.modules = modules
	return nil
}

// GetDependencyFilePattern return the dependency file pattern
func (v *Version) GetDependencyFilePattern() string {
	return v.dependencyFilePattern
}

// GetPackageManager return the package manager
func (v *Version) GetPackageManager() string {
	return "golang"
}

// GetLanguage return the package language
func (v *Version) GetLanguage() string {
	return "golang"
}

// ListAvailableVersions list all versions for depName
func (v *Version) ListAvailableVersions(ctx context.Context, depName string) ([]string, error) {
	return v.runner.listModuleVersions(ctx, depName)
}

// IsPreRelease check whether the version is prerelease version
func (v *Version) IsPreRelease(ctx context.Context, version string) (bool, error) {
	sv, err := semver.NewVersion(version)
	if err != nil {
		return false, err
	}
	return sv.Prerelease() != "", nil
}

// IsDirectDependency check whether it is the direct dependency
func (v *Version) IsDirectDependency(ctx context.Context, depName string) (bool, error) {
	module := v.modules[depName]
	if module == nil {
		return false, nil
	}

	return !module.Indirect, nil
}

// GetReleaseTime get the release time for multiple versions
func (v *Version) GetReleaseTime(ctx context.Context, depName string, versions ...string) (map[string]time.Time, error) {
	var releaseTimes = make(map[string]time.Time)
	for _, ve := range versions {
		releaseTime, err := v.getReleaseTime(ctx, depName, ve)
		if err != nil {
			return nil, err
		}
		releaseTimes[ve] = releaseTime
	}
	return releaseTimes, nil
}

// Sort versions in ascending order
func (v *Version) Sort(versions []string) error {
	vs := make([]*semver.Version, len(versions))
	for i, r := range versions {
		v, err := semver.NewVersion(r)
		if err != nil {
			return err
		}
		vs[i] = v
	}

	sort.Sort(semver.Collection(vs))
	for i, v := range vs {
		versions[i] = v.Original()
	}
	return nil
}

// Compare compares this version to another one. It returns -1, 0, or 1 if
// the new version smaller, equal, or larger than the old version
func (v *Version) Compare(newVersion, oldVersion string) (int, error) {
	sv1, err := semver.NewVersion(newVersion)
	if err != nil {
		return 0, err
	}

	sv2, err := semver.NewVersion(oldVersion)
	if err != nil {
		return 0, err
	}

	return sv1.Compare(sv2), nil
}

// IsBreakingChange check whether the version changed the major version
func (v *Version) IsBreakingChange(newVersion, oldVersion string) (bool, error) {
	sv1, err := semver.NewVersion(newVersion)
	if err != nil {
		return false, err
	}

	sv2, err := semver.NewVersion(oldVersion)
	if err != nil {
		return false, err
	}

	return sv1.Major() != sv2.Major(), nil
}

// AddDependency add the dependency to the dependency file and download it
func (v *Version) AddDependency(ctx context.Context, depName, version string) error {
	return v.runner.addModule(ctx, depName, version)
}

// UpdateDependencyFile tidy the dependency file
func (v *Version) UpdateDependencyFile(ctx context.Context) error {
	return v.runner.tidy(ctx)
}

// FindConflicts return the potential conflicts
func (v *Version) FindConflicts(ctx context.Context) (map[string][][]string, error) {
	buf, err := v.runner.runListRelationship(ctx)
	if err != nil {
		return nil, err
	}

	var root *node
	var nodeMap = make(map[string]*node)
	var scanner = bufio.NewScanner(buf)
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) != 2 {
			log.Warn("invalid go mod dependency relationship %s", scanner.Text())
			continue
		}

		from := fields[0]
		to := fields[1]
		fromNode := &node{depNameWithVersion: from}
		toNode := &node{depNameWithVersion: to}

		if _, ok := nodeMap[from]; !ok {
			nodeMap[from] = fromNode
		}
		if _, ok := nodeMap[to]; !ok {
			nodeMap[to] = toNode
		}

		nodeMap[from].child = append(nodeMap[from].child, toNode)
		if root == nil {
			root = nodeMap[from]
		}
	}

	var depNameMap = make(map[string][]*node)
	genDepNameMap(root, []string{}, depNameMap)

	var conflict = make(map[string][][]string)
	for depName, nodes := range depNameMap {
		if len(nodes) <= 1 {
			continue
		}

		// potential conflict
		var hasConflict = false
		for i := 1; i < len(nodes); i++ {
			if nodes[i].depNameWithVersion != nodes[i-1].depNameWithVersion {
				hasConflict = true
				break
			}
		}

		if hasConflict {
			for _, n := range nodes {
				conflict[depName] = append(conflict[depName], n.dependencyTrails)
			}
		}
	}

	return conflict, nil
}

// getReleaseTime get the version release time
func (v *Version) getReleaseTime(ctx context.Context, depName, version string) (time.Time, error) {
	module, err := v.runner.getModuleByName(ctx, depName, version)
	if err != nil {
		return time.Time{}, err
	}
	return module.Time, nil
}

func genDepNameMap(n *node, parentTrail []string, depNameMap map[string][]*node) {
	if n == nil {
		return
	}

	// fill in node's trails
	trails := make([]string, len(parentTrail))
	copy(trails, parentTrail)
	trails = append(trails, n.depNameWithVersion)
	n.dependencyTrails = trails

	// generate depName map
	arr := strings.Split(n.depNameWithVersion, "@")
	depNameMap[arr[0]] = append(depNameMap[arr[0]], n)

	// recursion
	for _, subNode := range n.child {
		genDepNameMap(subNode, trails, depNameMap)
	}
}
