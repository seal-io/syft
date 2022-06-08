package java

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common/command"
)

var (
	gradleDependencyPattern = regexp.MustCompile("^([ `+\\\\|-]+)([^ `+\\\\|-].+)$")
)

func newGradleScaffoldingParser(mode, currentFilepath, relativeFilepath string) *gradleScaffoldingParser {
	return &gradleScaffoldingParser{
		mode:             mode,
		currentFilepath:  currentFilepath,
		currentDir:       filepath.Dir(currentFilepath),
		relativeFilepath: relativeFilepath,
		relativeDir:      filepath.Dir(currentFilepath),
		command:          "gradle",
	}
}

type gradleScaffoldingParser struct {
	mode             string
	currentFilepath  string
	currentDir       string
	relativeFilepath string
	relativeDir      string
	command          string
}

// parse generate the packages and relationships for current project
func (p *gradleScaffoldingParser) parse(ctx context.Context) ([]*pkg.Package, []artifact.Relationship, error) {
	log.Infof("parsing gradle property for file %s", p.currentFilepath)
	isSubProject, curProj, projects, err := p.parseCurrentFile(ctx)
	if err != nil {
		return nil, nil, err
	}

	if isSubProject {
		// since root project can take over the full transitive dependencies,
		// ignore subprojects
		log.Infof("ignore gradle subproject dependency file %s", p.currentFilepath)
		return nil, nil, nil
	}

	if len(projects) == 0 {
		// main project name is ""
		projects = []string{""}
	}

	log.Infof("generating and parsing gradle dependency tree for %s", p.currentFilepath)
	pkgs, relationships, err := p.parseAllProjects(ctx, curProj, projects)
	if err != nil {
		return nil, nil, err
	}

	log.Infof("finished parsing gradle dependency file %s, found %d packages, %d relationships", p.currentFilepath, len(pkgs), len(relationships))
	return pkgs, relationships, nil
}

// nolint: nolintlint,funlen,gocognit
// parseProperty parse the project property from command output
func (p *gradleScaffoldingParser) parseCurrentFile(ctx context.Context) (bool, *pkg.PomProject, []string, error) {
	buf, err := p.runGetProperty(ctx)
	if err != nil {
		return false, nil, nil, err
	}

	var (
		buildFile                  string
		projects                   []string
		curProj                    = &pkg.PomProject{}
		propertiesCmdOutputScanner = bufio.NewScanner(buf)
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
			curProj.GroupID = groupStr
		case "name":
			nameStr := strings.TrimSpace(cols[1])
			curProj.Name = nameStr
			curProj.ArtifactID = nameStr
		case "version":
			versionStr := strings.TrimSpace(cols[1])
			if versionStr == "unspecified" {
				versionStr = ""
			}
			curProj.Version = versionStr
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
	if _, err := os.Stat(buildFile); err == nil && p.currentFilepath != buildFile {
		return true, nil, nil, nil
	}

	return false, curProj, projects, nil
}

// parseAllProjects get packages and relationships for all projects
func (p *gradleScaffoldingParser) parseAllProjects(ctx context.Context, mainProj *pkg.PomProject, projects []string) (pkgs []*pkg.Package, relations []artifact.Relationship, err error) {
	mainPkg, mainRelation, err := p.genCurrentFileDep()
	if err != nil {
		return nil, nil, err
	}

	pkgs = []*pkg.Package{mainPkg}
	relations = []artifact.Relationship{*mainRelation}
	for _, v := range projects {
		subProject, projectPkgs, projectRelations, err := p.parseSingleProject(ctx, mainProj, v)
		if err != nil {
			return nil, nil, err
		}

		pkgs = append(pkgs, projectPkgs...)
		relations = append(relations, projectRelations...)

		// handle relation main project -> subproject
		if v != "" {
			relations = append(relations, *toRelation(mainPkg, subProject))
		}
	}
	return pkgs, relations, nil
}

// parseSingleProject get packages and relationships for single project
func (p *gradleScaffoldingParser) parseSingleProject(
	ctx context.Context, mainProj *pkg.PomProject, project string,
) (*pkg.Package, []*pkg.Package, []artifact.Relationship, error) {
	buf, err := p.runGetDependencies(ctx, project)
	if err != nil {
		return nil, nil, nil, err
	}

	scanner := bufio.NewScanner(buf)
	directlyDeps, pkgs, relations, err := parseGraph(scanner, p.isValidDependencyLine, p.parseDependencyLineFn(mainProj))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse dependency graph %w", err)
	}

	// handle subprojects
	var subProjectPkg *pkg.Package
	if project != "" {
		name := strings.TrimPrefix(project, ":")
		subProjectPkg = toPackage(mainProj.GroupID, name, mainProj.Version, mainProj)
		pkgs = append(pkgs, subProjectPkg)
		for _, v := range directlyDeps {
			relations = append(relations, *toRelation(subProjectPkg, v))
		}
	}
	return subProjectPkg, pkgs, relations, nil
}

// nolint: nolintlint,goconst
func (p *gradleScaffoldingParser) runGetDependencies(ctx context.Context, project string) (io.Reader, error) {
	// NB(thxCode): choose `testRuntimeClasspath` as the only configuration,
	// ref to https://tomgregory.com/gradle-implementation-vs-compile-dependencies/.
	dependenciesCmdArgs := project + ":dependencies --quiet --no-daemon --console=plain --configuration=testRuntimeClasspath"
	switch p.mode {
	case "offline":
		dependenciesCmdArgs += " --offline"
	case "online", "":
	}

	return command.RunCommand(ctx, p.command, p.currentDir, strings.Split(dependenciesCmdArgs, " ")...)
}

// nolint: nolintlint,goconst
func (p *gradleScaffoldingParser) runGetProperty(ctx context.Context) (io.Reader, error) {
	// :properties show properties for root project;
	// properties show properties for current dir, if we run it under subproject A dir, we can only get subprojects for A,
	// we can get all subprojects while scan root project, so we use :properties here
	propertiesCmdArgs := ":properties --quiet --no-daemon --console=plain"
	switch p.mode {
	case "offline":
		propertiesCmdArgs += " --offline"
	case "online", "":
	}

	return command.RunCommand(ctx, p.command, p.currentDir, strings.Split(propertiesCmdArgs, " ")...)
}

func (p *gradleScaffoldingParser) genCurrentFileDep() (*pkg.Package, *artifact.Relationship, error) {
	to, err := pkg.FileToPackage(p.relativeFilepath)
	if err != nil {
		return nil, nil, err
	}

	from, err := pkg.FileToPackage(p.relativeDir)
	if err != nil {
		return nil, nil, err
	}

	return to, toRelation(from, to), nil
}

func (p *gradleScaffoldingParser) isValidDependencyLine(line string) bool {
	return gradleDependencyPattern.MatchString(line)
}

func (p *gradleScaffoldingParser) parseDependencyLineFn(mainProj *pkg.PomProject) parseLine {
	return func(line string) (int, *pkg.Package, error) {
		return p.parseDependencyLine(mainProj, line)
	}
}

// parseDependencyLine parse get package from dependency command output
func (p *gradleScaffoldingParser) parseDependencyLine(mainProj *pkg.PomProject, line string) (int, *pkg.Package, error) {
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
		childPkg = toPackage(mainProj.GroupID, name, mainProj.Version, mainProj)
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

		childPkg = toPackage(gav[0], gav[1], version, mainProj)
	}
	return prefixLen / 5, childPkg, nil
}
