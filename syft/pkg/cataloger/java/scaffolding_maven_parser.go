package java

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/google/uuid"
)

var (
	mavenDependencyPattern = regexp.MustCompile(`(?P<groupId>[-\w.+]+):(?P<artifactId>[-\w.+]+):(?P<type>[-\w.+]+):(?P<version>[-\w.+]+)`)
	mavenDigraphPattern    = regexp.MustCompile(`digraph \"[-:.\w]+\"`)
)

func newMavenScaffoldingParser(mode, fullFilepath, relativeFilePath string, reader io.Reader) *mavenScaffoldingParser {
	return &mavenScaffoldingParser{
		currentFilepath:  fullFilepath,
		currentDirPath:   filepath.Dir(fullFilepath),
		relativeFilePath: relativeFilePath,
		reader:           reader,
		mode:             mode,
	}
}

type mavenScaffoldingParser struct {
	currentFilepath  string
	currentDirPath   string
	relativeFilePath string
	reader           io.Reader
	mode             string
}

// parse generate the packages and relationships for current project
func (p *mavenScaffoldingParser) parse(ctx context.Context) (pkgs []*pkg.Package, relationships []artifact.Relationship, berr error) {
	// fetch main pkg
	log.Infof("parsing maven dependency file %s", p.currentFilepath)
	mainPkgPomProject, err := parsePomXML(p.currentFilepath, p.reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing pom xml: %w", err)
	}

	if p.isSubproject(mainPkgPomProject) {
		// since root project can take over the full transitive dependencies,
		// ignore subprojects
		log.Infof("ignore maven subproject dependency file %s", p.currentFilepath)
		return
	}

	// command output temp file
	depCmdOutputFile, err := ioutil.TempFile("", uuid.NewString())
	if err != nil {
		return nil, nil, fmt.Errorf("error creating maven transitive dependencies output file: %w", err)
	}
	defer func() {
		_ = depCmdOutputFile.Close()           // close
		_ = os.Remove(depCmdOutputFile.Name()) // remove
	}()

	log.Infof("downloading maven dependencies for %s", p.currentFilepath)
	dependenciesCmd, err := p.dependenciesCommand(ctx, depCmdOutputFile.Name())
	if err != nil {
		return nil, nil, err
	}

	err = dependenciesCmd.Run()
	if err != nil {
		return nil, nil, fmt.Errorf("error running maven transitive dependencies discovery: %w", err)
	}

	log.Infof("generating and parsing maven dependency tree for %s", p.currentFilepath)
	pkgs, relationships = p.parseDependencies(depCmdOutputFile, mainPkgPomProject)

	log.Infof("finished parsing maven dependency file %s, found %d packages, %d relationships", p.currentFilepath, len(pkgs), len(relationships))
	return pkgs, relationships, nil
}

// parseDependencies parse dependencies tree
func (p *mavenScaffoldingParser) parseDependencies(cmdOutputFile *os.File, mainPkgPomProject *pkg.PomProject) (pkgs []*pkg.Package, relationships []artifact.Relationship) {
	mainPkg, mainPkgRelation := p.packageFromPomProject(mainPkgPomProject)
	pkgs = append(pkgs, mainPkg)
	if mainPkgRelation != nil {
		relationships = append(relationships, *mainPkgRelation)
	}

	var dependenciesCmdOutputScanner = bufio.NewScanner(cmdOutputFile)
	for dependenciesCmdOutputScanner.Scan() {
		// process
		var line = dependenciesCmdOutputScanner.Text()
		if len(line) <= 0 {
			continue
		}

		var toPkg *pkg.Package
		var relation *artifact.Relationship
		var err error
		if strings.Contains(line, "->") {
			// type: dependency
			// line example: "org.apache.logging.log4j:log4j-core:jar:2.18.0:compile" -> "org.apache.logging.log4j:log4j-api:jar:2.18.0:compile" ;
			toPkg, relation, err = p.parseRelationLine(line, mainPkgPomProject)
		} else if mavenDigraphPattern.MatchString(line) {
			// type: digraph
			// line example: digraph "io.seal.simple:simple-java-maven-app:jar:1.0-SNAPSHOT"
			toPkg, relation, err = p.parseDigraphLine(line, mainPkgPomProject)
		}

		if err != nil {
			log.Warnf("failed to parse line %s from maven dependency tree, %v", line, err)
			continue
		}

		if toPkg != nil && relation != nil {
			relationships = append(relationships, *relation)
			pkgs = append(pkgs, toPkg)
		}
	}

	return
}

// parseRelationLine handle the line include relation
func (p *mavenScaffoldingParser) parseRelationLine(line string, pomProject *pkg.PomProject) (*pkg.Package, *artifact.Relationship, error) {
	// line example: "org.apache.logging.log4j:log4j-core:jar:2.18.0:compile" -> "org.apache.logging.log4j:log4j-api:jar:2.18.0:compile" ;
	arr := strings.Split(line, "->")
	if len(arr) < 2 {
		return nil, nil, fmt.Errorf("invalid maven dependency relation %s", line)
	}

	// rough example: "org.apache.logging.log4j:log4j-api:jar:2.18.0:compile"
	lRough := strings.TrimSpace(arr[0])
	if len(lRough) < 2 {
		return nil, nil, fmt.Errorf("invalid maven dependency relation, source %s", arr[0])
	}

	// rough example: "org.apache.logging.log4j:log4j-api:jar:2.18.0:compile" ;
	rRough := strings.TrimSpace(arr[1])
	if len(rRough) < 4 {
		return nil, nil, fmt.Errorf("invalid maven dependency relation, destination %s", arr[1])
	}

	lAccurate := lRough[1 : len(lRough)-1]
	rAccurate := rRough[1 : len(rRough)-3]
	fromPkg, err := p.packageFromGavStr(lAccurate, pomProject)
	if err != nil {
		return nil, nil, err
	}

	toPkg, err := p.packageFromGavStr(rAccurate, pomProject)
	if err != nil {
		return nil, nil, err
	}

	fromID := &PackageURL{Package: *fromPkg}
	toID := &PackageURL{Package: *toPkg}
	relation := &artifact.Relationship{
		From: fromID,
		To:   toID,
		Type: artifact.DependencyOfRelationship,
	}
	return toPkg, relation, nil
}

// parseDigraphLine handle the line include digraph info
func (p *mavenScaffoldingParser) parseDigraphLine(line string, pomProject *pkg.PomProject) (*pkg.Package, *artifact.Relationship, error) {
	// line example: } digraph "io.seal.simple:child-1:jar:1.0-SNAPSHOT" {
	matches := mavenDependencyPattern.FindStringSubmatch(line)
	if len(matches) < 5 {
		return nil, nil, fmt.Errorf("invalid maven digraph %s", line)
	}

	groupID := matches[1]
	artifactID := matches[2]
	version := matches[4]

	if artifactID == pomProject.ArtifactID &&
		groupID == pomProject.GroupID &&
		version == pomProject.Version {
		return nil, nil, nil
	}

	pkg := toPackage(groupID, artifactID, version, "", false, pomProject)
	mainPkg, _ := p.packageFromPomProject(pomProject)
	fromID := &PackageURL{Package: *mainPkg}
	toID := &PackageURL{Package: *pkg}
	relation := &artifact.Relationship{
		From: fromID,
		To:   toID,
		Type: artifact.DependencyOfRelationship,
	}
	return pkg, relation, nil
}

func (p *mavenScaffoldingParser) isSubproject(project *pkg.PomProject) bool {
	if p.relativeFilePath == "pom.xml" {
		return false
	}

	if project.Parent == nil {
		return false
	}

	if project.GroupID != "" && project.GroupID != project.Parent.GroupID {
		return false
	}

	baseDir := strings.TrimSuffix(p.currentFilepath, p.relativeFilePath)
	grandParentDir := filepath.Dir(filepath.Dir(p.relativeFilePath))
	for _, v := range filepath.SplitList(grandParentDir) {
		_, err := os.Stat(filepath.Join(baseDir, v, "pom.xml"))
		if err == nil {
			return true
		}
	}
	return false
}

func (p *mavenScaffoldingParser) dependenciesCommand(ctx context.Context, outputFileName string) (*exec.Cmd, error) {
	var cmdArgs = "org.apache.maven.plugins:maven-dependency-plugin:3.3.0:tree -DoutputType=dot -DappendOutput=true --fail-fast"
	switch p.mode {
	case "offline":
		cmdArgs += " --offline"
	case "online", "":
	}

	cmdArgs += " -DoutputFile=" + outputFileName
	cmd, err := newCommand(ctx, "mvn", strings.Split(cmdArgs, " ")...)
	if err != nil {
		return nil, fmt.Errorf("error creating maven transitive dependencies discovery: %w", err)
	}
	cmd.Dir = p.currentDirPath
	return cmd, nil
}

func (p *mavenScaffoldingParser) packageFromPomProject(mainPkgPomProject *pkg.PomProject) (*pkg.Package, *artifact.Relationship) {
	mainPkg := toPackage(
		mainPkgPomProject.GroupID,
		mainPkgPomProject.ArtifactID,
		mainPkgPomProject.Version,
		p.currentFilepath,
		true,
		mainPkgPomProject,
	)

	if mainPkgPomProject.Parent == nil {
		return mainPkg, nil
	}

	parentPkg := toPackage(
		mainPkgPomProject.Parent.GroupID,
		mainPkgPomProject.Parent.ArtifactID,
		mainPkgPomProject.Parent.Version,
		"",
		false,
		nil,
	)

	return mainPkg, &artifact.Relationship{
		From: &PackageURL{Package: *parentPkg},
		To:   &PackageURL{Package: *mainPkg},
		Type: artifact.DevDependencyOfRelationship,
	}
}

func (p *mavenScaffoldingParser) packageFromGavStr(gav string, mainProject *pkg.PomProject) (*pkg.Package, error) {
	// pkgStr format: group:artifact:package-type:version:scope
	gavArr := strings.Split(gav, ":")
	if len(gavArr) < 4 {
		return nil, fmt.Errorf("invalid package string %s", gav)
	}

	return toPackage(gavArr[0], gavArr[1], gavArr[3], "", false, mainProject), nil
}
