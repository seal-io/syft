package java

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/anchore/syft/syft/pkg/command"
	mvnversion "github.com/masahiro331/go-mvn-version"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html"
)

const (
	timeFormat             = "2006-01-02 15:04"
	defaultMavenRepository = "https://repo1.maven.org/maven2"
)

var (
	preReleaseQualifiers = []string{"alpha", "beta", "milestone", "rc", "cr", "snapshot"}
)

var client *fasthttp.Client = FastClient()

func FastClient() *fasthttp.Client {
	return &fasthttp.Client{
		NoDefaultUserAgentHeader: false,
		ReadTimeout:              10 * time.Second,
		MaxConnDuration:          10 * time.Minute,
		MaxConnWaitTimeout:       10 * time.Second,
		MaxIdleConnDuration:      10 * time.Second,
		// respect the request retry backoff of HttpRequest
		MaxIdemponentCallAttempts: 1,
	}
}

type MavenMetadata struct {
	GroupId    string   `xml:"groupId"`
	ArtifactId string   `xml:"artifactId"`
	Versions   []string `xml:"versioning>versions>version"`
}

func NewMaven() *Version {
	return &Version{
		command:               "mvn",
		dependencyFilePattern: pomFilePattern,
		mavenRepository:       defaultMavenRepository,
	}
}

type Version struct {
	command               string
	workspaceDir          string
	dependencyFilePattern string
	dependencyFilePath    string
	mavenRepository       string
	pomProject            *gopom.Project
}

type node struct {
	depNameWithVersion string // dependency name with version
	child              []*node
	dependencyTrails   []string
}

// Init set the workspace for running command
func (v *Version) Init(ctx context.Context, workspace, registry string) error {
	v.workspaceDir = workspace
	if registry != "" {
		v.mavenRepository = registry
	}

	// init with pom project
	pomFile := filepath.Join(v.workspaceDir, "pom.xml")
	file, err := os.Open(pomFile)
	if err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	pomProject, err := decodePomXML(reader)
	if err != nil {
		return err
	}
	v.pomProject = &pomProject
	return nil
}

// GetDependencyFilePattern return the dependency file pattern
func (v *Version) GetDependencyFilePattern() string {
	return v.dependencyFilePattern
}

// GetPackageManager return the package manager
func (v *Version) GetPackageManager() string {
	return "maven"
}

// GetLanguage return the package language
func (v *Version) GetLanguage() string {
	return "java"
}

// ListAvailableVersions list all versions for depName
func (v *Version) ListAvailableVersions(ctx context.Context, depName string) ([]string, error) {
	address, err := url.Parse(v.mavenRepository)
	if err != nil {
		return nil, err
	}

	address.Path = path.Join(address.Path, strings.ReplaceAll(depName, ".", "/"), "maven-metadata.xml")
	statusCode, resp, err := client.Get(nil, address.String())
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get %s, unexpected status code: %d, expecting %d", address.String(), statusCode, http.StatusOK)
	}

	metadata := &MavenMetadata{}
	if err = xml.Unmarshal(resp, metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata from %s: %w", address.String(), err)
	}

	return metadata.Versions, nil
}

// IsPreRelease check whether the version is prerelease version
func (v *Version) IsPreRelease(ctx context.Context, version string) (bool, error) {
	sver, err := mvnversion.NewVersion(version)
	if err != nil {
		return false, err
	}

	for _, item := range sver.Items {
		switch it := item.(type) {
		case mvnversion.StringItem:
			for _, qualifier := range preReleaseQualifiers {
				if strings.Contains(fmt.Sprintf("%v", it), qualifier) {
					return true, nil
				}
			}
		default:
			continue
		}
	}
	return false, nil
}

// IsDirectDependency check whether it is the direct dependency
func (v *Version) IsDirectDependency(ctx context.Context, depName string) (bool, error) {
	for _, v := range v.pomProject.Dependencies {
		directDepName := fmt.Sprintf("%s/%s", v.GroupID, v.ArtifactID)
		if directDepName == depName {
			return true, nil
		}
	}
	return false, nil
}

// GetReleaseTime get the version release time
func (v *Version) GetReleaseTime(ctx context.Context, depName string, versions ...string) (map[string]time.Time, error) {
	address, err := url.Parse(v.mavenRepository)
	if err != nil {
		return nil, err
	}
	address.Path = path.Join(address.Path, strings.ReplaceAll(depName, ".", "/"))
	statusCode, resp, err := client.Get(nil, address.String())
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get %s, unexpected status code: %d, expecting %d", address.String(), statusCode, http.StatusOK)
	}

	releaseInfo := make(map[string]time.Time)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp))
	if err != nil {
		return nil, err
	}

	doc.Find("#contents").Contents().Each(func(i int, s *goquery.Selection) {
		if goquery.NodeName(s) != "#text" || i == 0 {
			return
		}

		// get version
		var titleNode = doc.Find("#contents").Contents().Get(i - 1)
		var attr = getAttr("title", titleNode)
		if attr == nil {
			return
		}
		var version = strings.TrimSuffix(attr.Val, "/")

		// get release time
		var arr = strings.Split(strings.TrimSpace(s.Text()), " ")
		if len(arr) < 2 {
			return
		}
		var txt = fmt.Sprintf("%s %s", arr[0], arr[1])
		releaseTime, err := time.Parse(timeFormat, txt)
		if err != nil {
			logrus.Warnf("invalid release time %s from %s: %v", s.Text(), address.String(), err)
			return
		}
		releaseInfo[version] = releaseTime
	})

	var versionMap = make(map[string]time.Time)
	for _, name := range versions {
		versionMap[name] = releaseInfo[name]
	}

	return versionMap, nil
}

// Sort versions in ascending order
func (v *Version) Sort(versions []string) error {
	sort.SliceStable(versions, func(i, j int) bool {
		v1, err := mvnversion.NewVersion(versions[i])
		if err != nil {
			logrus.Warnf("failed to parse maven package version %s, %v", versions[i], err)
			return false
		}

		v2, err := mvnversion.NewVersion(versions[j])
		if err != nil {
			logrus.Warnf("failed to parse maven package version %s, %v", versions[i], err)
			return false
		}
		return v1.LessThan(v2)
	})
	return nil
}

// Compare compares this version to another one. It returns -1, 0, or 1 if
// the new version smaller, equal, or larger than the old version
func (v *Version) Compare(newVersion, oldVersion string) (int, error) {
	v1, err := mvnversion.NewVersion(newVersion)
	if err != nil {
		return 0, err
	}

	v2, err := mvnversion.NewVersion(oldVersion)
	if err != nil {
		return 0, err
	}

	return v1.Compare(v2), nil
}

// IsBreakingChange check whether the version changed the major version
func (v *Version) IsBreakingChange(newVersion, oldVersion string) (bool, error) {
	v1, err := mvnversion.NewVersion(newVersion)
	if err != nil {
		return false, err
	}

	v2, err := mvnversion.NewVersion(oldVersion)
	if err != nil {
		return false, err
	}

	return v1.Items[0].Compare(v2.Items[0]) != 0, nil
}

// AddDependency add the dependency to the dependency file
func (v *Version) AddDependency(ctx context.Context, depName, version string) error {
	var isVersionInProperty = false
	var versionProp string
	var arr = strings.Split(depName, "/")
	var artifactID = arr[len(arr)-1]
	var groupID = strings.TrimSuffix(depName, "/"+artifactID)
	var dep = v.getDependency(groupID, artifactID)
	if dep != nil && strings.HasPrefix(dep.Version, "${") {
		isVersionInProperty = true
		key := strings.TrimSuffix(strings.TrimPrefix(dep.Version, "${"), "}")
		versionProp = v.getProperty(key)
	}

	// version defined in property
	if isVersionInProperty && versionProp != "" {
		args := "-B org.codehaus.mojo:versions-maven-plugin:2.12.0:set-property -Dproperty=" + versionProp + "-DnewVersion=" + version + "-DgenerateBackupPoms=false"
		_, err := command.RunCommand(ctx, v.command, v.workspaceDir, strings.Split(args, " ")...)
		if err != nil {
			return fmt.Errorf("failed to update property %s: %w", versionProp, err)
		}
		return nil
	}

	// version defined in dependency
	args := "-B org.codehaus.mojo:versions-maven-plugin:2.12.0:use-dep-version -Dincludes=" + depName + " -DdepVersion=" + version + " -DgenerateBackupPoms=false"
	_, err := command.RunCommand(ctx, v.command, v.workspaceDir, strings.Split(args, " ")...)
	if err != nil {
		return fmt.Errorf("failed to add dependency %s@%s: %w", depName, version, err)
	}

	// TODO(michelia): support for more complex scenarios
	// 1. handle property version used by multiple place, may affect other package
	// 2. handle version from parent pom
	return nil
}

// UpdateDependencyFile tidy the dependency file and download the dependency
func (v *Version) UpdateDependencyFile(ctx context.Context) error {
	// maven no need to tidy the dependency file
	return nil
}

// FindConflicts return the potential conflicts
func (v *Version) FindConflicts(ctx context.Context) (map[string][][]string, error) {
	// mvn org.apache.maven.plugins:maven-enforcer-plugin:3.1.0:enforce -Drules=dependencyConvergence -Denforcer.fail=false
	args := "org.apache.maven.plugins:maven-enforcer-plugin:3.1.0:enforce -Drules=dependencyConvergence -Denforcer.fail=false"
	buf, err := command.RunCommand(ctx, v.command, v.workspaceDir, strings.Split(args, " ")...)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dependency graph: %w", err)
	}

	return parseDependencyConvergence(bufio.NewScanner(buf))
}

func (v *Version) getProperty(name string) string {
	for k, e := range v.pomProject.Properties.Entries {
		if k == name {
			return e
		}
	}
	return ""
}

func (v *Version) getDependency(groupID, artifactID string) *gopom.Dependency {
	for i, d := range v.pomProject.Dependencies {
		if d.GroupID == groupID && d.ArtifactID == artifactID {
			return &v.pomProject.Dependencies[i]
		}
	}
	return nil
}

/*
example:
[WARNING]
Dependency convergence error for com.google.http-client:google-http-client:jar:1.31.0:compile paths to dependency are:
+-com.example.deps.example1:example1-simple:jar:1.0-SNAPSHOT
  +-com.google.cloud:google-cloud-translate:jar:1.90.0:compile
    +-com.google.cloud:google-cloud-core-http:jar:1.90.0:compile
      +-com.google.auth:google-auth-library-oauth2-http:jar:0.17.1:compile
        +-com.google.http-client:google-http-client:jar:1.31.0:compile
and
+-com.example.deps.example1:example1-simple:jar:1.0-SNAPSHOT
  +-com.google.cloud:google-cloud-translate:jar:1.90.0:compile
    +-com.google.cloud:google-cloud-core-http:jar:1.90.0:compile
      +-com.google.auth:google-auth-library-oauth2-http:jar:0.17.1:compile
        +-com.google.http-client:google-http-client-jackson2:jar:1.31.0:compile
          +-com.google.http-client:google-http-client:jar:1.31.0:compile
*/

func parseDependencyConvergence(scanner *bufio.Scanner) (map[string][][]string, error) {
	var conflicts = make(map[string][][]string)
	var depName string
	var parents []string
	for scanner.Scan() {
		var line = scanner.Text()
		if strings.HasPrefix(line, "Dependency convergence error") {
			matches := mavenDependencyPattern.FindStringSubmatch(line)
			groupID := matches[1]
			artifactID := matches[2]
			depName = fmt.Sprintf("%s/%s", groupID, artifactID)
			continue
		}

		level := strings.Index(line, "+-")
		if level == -1 {
			// set previous dependency conflict trails
			if depName != "" && len(parents) != 0 {
				conflicts[depName] = append(conflicts[depName], parents)
			}
			parents = []string{}
			continue
		}

		rough := line[level+2:]
		matches := mavenDependencyPattern.FindStringSubmatch(rough)
		if len(matches) < 5 {
			return nil, fmt.Errorf("invalid maven dependency convergence %s", line)
		}

		groupID := matches[1]
		artifactID := matches[2]
		version := matches[4]
		parents = append(parents, fmt.Sprintf("%s/%s@%s", groupID, artifactID, version))
	}

	return conflicts, nil
}

func getAttr(attrName string, n *html.Node) *html.Attribute {
	if n == nil {
		return nil
	}

	for i, a := range n.Attr {
		if a.Key == attrName {
			return &n.Attr[i]
		}
	}
	return nil
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
