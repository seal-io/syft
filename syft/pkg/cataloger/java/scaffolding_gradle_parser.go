package java

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

var (
	gradleDependencyPattern = regexp.MustCompile("^([ `+\\\\|-]+)([^ `+\\\\|-].+)$")
)

func newGradleScaffoldingParser(mode, currentFilePath string) *gradleScaffoldingParser {
	return &gradleScaffoldingParser{
		mode:            mode,
		currentFilePath: currentFilePath,
		currentDirPath:  filepath.Dir(currentFilePath),
	}
}

type gradleScaffoldingParser struct {
	mode            string
	currentFilePath string
	currentDirPath  string
	mainProject     *pkg.PomProject
}

// parse generate the packages and relationships for current project
func (p *gradleScaffoldingParser) parse(ctx context.Context) ([]*pkg.Package, []artifact.Relationship, error) {
	log.Infof("parsing gradle dependency file %s", p.currentFilePath)

	log.Infof("parsing gradle property for file %s", p.currentFilePath)
	isSubProject, mainPkg, projects, err := p.parseProperty(ctx)
	if err != nil {
		return nil, nil, err
	}

	if isSubProject {
		// since root project can take over the full transitive dependencies,
		// ignore subprojects
		log.Infof("ignore gradle subproject dependency file %s", p.currentFilePath)
		return nil, nil, nil
	}

	p.mainProject = mainPkg
	if len(projects) == 0 {
		// main project name is ""
		projects = []string{""}
	}

	log.Infof("generating and parsing gradle dependency tree for %s", p.currentFilePath)
	pkgs, relationships, err := p.parseAllProjects(ctx, projects)
	if err != nil {
		return nil, nil, err
	}

	log.Infof("finished parsing gradle dependency file %s, found %d packages, %d relationships", p.currentFilePath, len(pkgs), len(relationships))
	return pkgs, relationships, nil
}

// parseProperty parse the project property from command output
func (p *gradleScaffoldingParser) parseProperty(ctx context.Context) (bool, *pkg.PomProject, []string, error) {
	propertiesCmd, err := p.propertyCommand(ctx)
	if err != nil {
		return false, nil, nil, err
	}

	propertiesCmdOutput, err := propertiesCmd.CombinedOutput()
	if err != nil {
		return false, nil, nil, fmt.Errorf("error running gradle properties discovery: %w", err)
	}

	var (
		buildFile                  string
		projects                   []string
		mainProject                = &pkg.PomProject{}
		propertiesCmdOutputScanner = bufio.NewScanner(bytes.NewBuffer(propertiesCmdOutput))
	)

	for propertiesCmdOutputScanner.Scan() {
		var line = propertiesCmdOutputScanner.Text()
		var cols = strings.SplitN(line, ":", 2)
		switch cols[0] {
		default:
			continue
		case "buildFile":
			buildFile = strings.TrimSpace(cols[1])
		case "group":
			groupStr := strings.TrimSpace(cols[1])
			mainProject.GroupID = groupStr
		case "name":
			nameStr := strings.TrimSpace(cols[1])
			mainProject.Name = nameStr
			mainProject.ArtifactID = nameStr
		case "version":
			versionStr := strings.TrimSpace(cols[1])
			if versionStr == "unspecified" {
				versionStr = ""
			}
			mainProject.Version = versionStr
		case "subprojects":
			subprojectsStr := strings.TrimSpace(cols[1])
			if subprojectsStr == "[]" {
				continue
			}
			if subprojectsStr[0] == '[' && subprojectsStr[len(subprojectsStr)-1] == ']' {
				subprojectsStr = subprojectsStr[1 : len(subprojectsStr)-1]
			}
			subprojects := strings.Split(subprojectsStr, ", ")
			for i := range subprojects {
				var subproject = subprojects[i]
				subproject = strings.TrimPrefix(subproject, "project ")
				if len(subproject) != 0 && subproject[0] == '\'' && subproject[len(subproject)-1] == '\'' {
					subproject = subproject[1 : len(subproject)-1]
				}
				projects = append(projects, subproject)
			}
		}
	}

	// current file isn't build file and root buildFile existed
	if _, err := os.Stat(buildFile); err == nil && p.currentFilePath != buildFile {
		return true, nil, nil, nil
	}

	return false, mainProject, projects, nil
}

// parseAllProjects get packages and relationships for all projects
func (p *gradleScaffoldingParser) parseAllProjects(ctx context.Context, projects []string) (allPkgs []*pkg.Package, relations []artifact.Relationship, err error) {
	mainPkg := toPackage(p.mainProject.GroupID, p.mainProject.ArtifactID, p.mainProject.Version, p.currentFilePath, true, p.mainProject)
	allPkgs = append(allPkgs, mainPkg)
	for _, v := range projects {
		subProject, projectPkgs, projectRelations, err := p.parseSingleProject(ctx, v)
		if err != nil {
			return nil, nil, err
		}

		allPkgs = append(allPkgs, projectPkgs...)
		relations = append(relations, projectRelations...)

		// handle relation main project -> subproject
		if v != "" {
			fromID := &PackageURL{Package: *mainPkg}
			toID := &PackageURL{Package: *subProject}
			relations = append(relations, artifact.Relationship{
				From: fromID,
				To:   toID,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}
	return allPkgs, relations, nil
}

// parseSingleProject get packages and relationships for single project
func (p *gradleScaffoldingParser) parseSingleProject(ctx context.Context, project string) (*pkg.Package, []*pkg.Package, []artifact.Relationship, error) {
	cmd, err := p.dependenciesCommand(ctx, project)
	if err != nil {
		return nil, nil, nil, err
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error running gradle transitive dependencies discovery: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewBuffer(output))
	directlyDeps, allPkgs, relations, err := parseGraph(scanner, p.isValidDependencyLine, p.parseDependencyLine)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error parse graph from command %s, %w", cmd.String(), err)
	}

	// handle subprojects
	var subProjectPkg *pkg.Package
	if project != "" {
		name := strings.TrimPrefix(project, ":")
		subProjectPkg = toPackage(p.mainProject.GroupID, name, p.mainProject.Version, "", false, p.mainProject)
		allPkgs = append(allPkgs, subProjectPkg)

		fromID := &PackageURL{Package: *subProjectPkg}
		for _, v := range directlyDeps {
			var toID = &PackageURL{Package: *v}
			relations = append(relations, artifact.Relationship{
				From: fromID,
				To:   toID,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}
	return subProjectPkg, allPkgs, relations, nil
}

func (p *gradleScaffoldingParser) dependenciesCommand(ctx context.Context, project string) (*exec.Cmd, error) {
	// NB(thxCode): choose `testRuntimeClasspath` as the only configuration,
	// ref to https://tomgregory.com/gradle-implementation-vs-compile-dependencies/.
	dependenciesCmdArgs := project + ":dependencies --quiet --no-daemon --console=plain --configuration=testRuntimeClasspath"
	switch p.mode {
	case "offline":
		dependenciesCmdArgs += " --offline"
	case "online", "":
	}

	dependenciesCmd, err := newCommand(ctx, "gradle", strings.Split(dependenciesCmdArgs, " ")...)
	if err != nil {
		return nil, fmt.Errorf("error creating gradle transitive dependencies discovery: %w", err)
	}
	dependenciesCmd.Dir = p.currentDirPath
	return dependenciesCmd, nil
}

func (p *gradleScaffoldingParser) propertyCommand(ctx context.Context) (*exec.Cmd, error) {
	// :properties show properties for root project;
	// properties show properties for current dir, if we run it under subproject A dir, we can only get subprojects for A,
	// we can get all subprojects while scan root project, so we use :properties here
	propertiesCmdArgs := ":properties --quiet --no-daemon --console=plain"
	switch p.mode {
	case "offline":
		propertiesCmdArgs += " --offline"
	case "online", "":
	}

	propertiesCmd, err := newCommand(ctx, "gradle", strings.Split(propertiesCmdArgs, " ")...)
	if err != nil {
		return nil, fmt.Errorf("error creating gradle properties discovery: %w", err)
	}
	propertiesCmd.Dir = p.currentDirPath
	return propertiesCmd, nil
}

func (p *gradleScaffoldingParser) isValidDependencyLine(line string) bool {
	return gradleDependencyPattern.MatchString(line)
}

// parseDependencyLine parse get package from dependency command output
func (p *gradleScaffoldingParser) parseDependencyLine(line string) (int, *pkg.Package, error) {
	matches := gradleDependencyPattern.FindStringSubmatch(line)
	prefixLen := len(matches[1])
	if prefixLen%5 != 0 {
		return 0, nil, fmt.Errorf("invalid gradle dependency line %s", line)
	}

	accurate := strings.TrimSuffix(strings.TrimSuffix(matches[2], " (*)"), " (n)")
	accurate = strings.TrimSuffix(accurate, " FAILED") // for offline

	var childPkg *pkg.Package
	if strings.HasPrefix(accurate, "project ") {
		// project example:
		// \--- project :typical-project-name
		// \--- project no-colons-in-project-name (n)

		// construct
		name := strings.TrimPrefix(strings.TrimPrefix(accurate, "project "), ":")
		childPkg = toPackage(p.mainProject.GroupID, name, p.mainProject.Version, "", false, p.mainProject)
	} else {
		// package example:
		//  1. group:project:requestedVersion
		//  2. group:project:requestedVersion -> resolvedVersion
		//  3. group:project -> resolvedVersion

		sections := strings.Split(accurate, " -> ")
		// gav example:
		// group:artifact:version
		// example:
		// implementation 'com.github.gavlyukovskiy:p6spy-spring-boot-starter:1.6.3'
		// implementation 'org.junit.jupiter:junit-jupiter-api'
		gav := strings.SplitN(sections[0], ":", 3)
		if len(gav) < 2 {
			return 0, nil, fmt.Errorf("invalid gav format %s", accurate)
		}

		// resolved version
		var version string
		if len(gav) == 3 {
			version = gav[2]
		}
		if len(sections) == 2 {
			version = sections[1]
		}

		childPkg = toPackage(gav[0], gav[1], version, "", false, p.mainProject)
	}
	return prefixLen / 5, childPkg, nil
}
