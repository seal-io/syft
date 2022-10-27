package java

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common/command"
	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

const (
	// PackagingTypePom means packaging type pom in pom.xml, which helps to create aggregators and parent projects.
	PackagingTypePom = "pom"
)

var (
	mavenDependencyPattern = regexp.MustCompile(`(?P<groupId>[-\w.+]+):(?P<artifactId>[-\w.+]+):(?P<type>[-\w.+]+):(?P<version>[-\w.+]+)`)
	mavenDigraphPattern    = regexp.MustCompile(`digraph \"[-:.\w]+\"`)
)

func newMavenScaffoldingParser(mode, fullFilepath, relativeFilePath string, reader io.Reader, src *source.Source) *mavenScaffoldingParser {
	return &mavenScaffoldingParser{
		currentFilepath:  fullFilepath,
		currentDirPath:   filepath.Dir(fullFilepath),
		relativeFilePath: relativeFilePath,
		reader:           reader,
		mode:             mode,
		source:           src,
		command:          "mvn",
	}
}

type mavenScaffoldingParser struct {
	currentFilepath  string
	currentDirPath   string
	relativeFilePath string
	reader           io.Reader
	mode             string
	source           *source.Source
	command          string
}

// parse generate the packages and relationships for current project
func (p *mavenScaffoldingParser) parse(ctx context.Context) (pkgs []*pkg.Package, relationships []artifact.Relationship, berr error) {
	log.Infof("parsing maven dependency file %s", p.currentFilepath)
	isAggregatePom, curProj, err := p.parseCurrentPomFile()
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing pom xml: %w", err)
	}

	if isAggregatePom {
		// since the sub pom file can include all their dependencies, includes the configures inherited from aggregate pom file,
		// and while user just defined parent configure in the submodules, we won't be able to detect them.
		// so ignore the aggregate pom file
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
	if err = p.runGetDependencies(ctx, depCmdOutputFile.Name()); err != nil {
		return nil, nil, err
	}

	log.Infof("generating and parsing maven dependency tree for %s", p.currentFilepath)
	pkgs, relationships, err = p.parseDependencies(depCmdOutputFile, curProj)
	if err != nil {
		return nil, nil, err
	}

	log.Infof("finished parsing maven dependency file %s, found %d packages, %d relationships", p.currentFilepath, len(pkgs), len(relationships))
	return pkgs, relationships, nil
}

// parseCurrentFile return whether current pom.xml is aggregate packaging type and get project from pom.xml
func (p *mavenScaffoldingParser) parseCurrentPomFile() (bool, *pkg.PomProject, error) {
	pom, err := decodePomXML(p.reader)
	if err != nil {
		return false, nil, fmt.Errorf("error parsing pom xml: %w", err)
	}

	if pom.Packaging == PackagingTypePom {
		return true, nil, nil
	}

	return false, newPomProject(p.relativeFilePath, pom), nil
}

// parseDependencies parse dependencies tree
func (p *mavenScaffoldingParser) parseDependencies(cmdOutputFile *os.File, curProj *pkg.PomProject) (pkgs []*pkg.Package, relationships []artifact.Relationship, err error) {
	curPkg, curRelation, err := p.genCurrentFileDep()
	if err != nil {
		return nil, nil, err
	}

	pkgs = []*pkg.Package{curPkg}
	relationships = []artifact.Relationship{*curRelation}
	dependenciesCmdOutputScanner := bufio.NewScanner(cmdOutputFile)
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
			toPkg, relation, err = p.parseRelationLine(line, curProj, curPkg)
		} else if mavenDigraphPattern.MatchString(line) {
			// type: digraph
			// line example: digraph "io.seal.simple:simple-java-maven-app:jar:1.0-SNAPSHOT"
			toPkg, relation, err = p.parseDigraphLine(line, curPkg, curProj)
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
func (p *mavenScaffoldingParser) parseRelationLine(line string, curProj *pkg.PomProject, curPkg *pkg.Package) (*pkg.Package, *artifact.Relationship, error) {
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
	fromGroupID, fromArtifactID, fromVersion, err := p.gavFromStr(lAccurate)
	if err != nil {
		return nil, nil, err
	}

	fromPkg := toPackage(fromGroupID, fromArtifactID, fromVersion, curProj)
	if isCurrentProject(fromGroupID, fromArtifactID, fromVersion, curProj) {
		fromPkg = curPkg
	}

	toGroupID, toArtifactID, toVersion, err := p.gavFromStr(rAccurate)
	if err != nil {
		return nil, nil, err
	}
	toPkg := toPackage(toGroupID, toArtifactID, toVersion, curProj)
	relation := toRelation(fromPkg, toPkg)
	return toPkg, relation, nil
}

// parseDigraphLine handle the line include digraph info
func (p *mavenScaffoldingParser) parseDigraphLine(line string, curPkg *pkg.Package, curProj *pkg.PomProject) (*pkg.Package, *artifact.Relationship, error) {
	// line example: } digraph "io.seal.simple:child-1:jar:1.0-SNAPSHOT" {
	matches := mavenDependencyPattern.FindStringSubmatch(line)
	if len(matches) < 5 {
		return nil, nil, fmt.Errorf("invalid maven digraph %s", line)
	}

	groupID := matches[1]
	artifactID := matches[2]
	version := matches[4]

	if isCurrentProject(groupID, artifactID, version, curProj) {
		return nil, nil, nil
	}

	pkg := toPackage(groupID, artifactID, version, curProj)
	relation := toRelation(curPkg, pkg)
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

func (p *mavenScaffoldingParser) genCurrentFileDep() (*pkg.Package, *artifact.Relationship, error) {
	to, err := pkg.FileToPackage(p.relativeFilePath)
	if err != nil {
		return nil, nil, err
	}

	from, err := pkg.FileToPackage(p.source.Metadata.Path)
	if err != nil {
		return nil, nil, err
	}

	return to, toRelation(from, to), nil
}

func (p *mavenScaffoldingParser) runGetDependencies(ctx context.Context, outputFileName string) error {
	var cmdArgs = "org.apache.maven.plugins:maven-dependency-plugin:3.3.0:tree -DoutputType=dot -DappendOutput=true --fail-fast"
	switch p.mode {
	case "offline":
		cmdArgs += " --offline"
	case "online", "":
	}

	cmdArgs += " -DoutputFile=" + outputFileName
	stderr := &bytes.Buffer{}
	cmd, err := command.NewCommand(ctx, p.command, p.currentDirPath, nil, stderr, strings.Split(cmdArgs, " ")...)
	if err != nil {
		return fmt.Errorf("error creating maven transitive dependencies discovery: %w", err)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error running maven transitive dependencies discovery: %w, stderr: %s", err, stderr.String())
	}
	return nil
}

func (p *mavenScaffoldingParser) gavFromStr(gav string) (string, string, string, error) {
	// pkgStr format: group:artifact:package-type:version:scope
	gavArr := strings.Split(gav, ":")
	if len(gavArr) < 4 {
		return "", "", "", fmt.Errorf("invalid package string %s", gav)
	}

	return gavArr[0], gavArr[1], gavArr[3], nil
}

func isCurrentProject(groupID, artifactID, version string, curProj *pkg.PomProject) bool {
	return artifactID == curProj.ArtifactID &&
		groupID == curProj.GroupID &&
		version == curProj.Version
}
