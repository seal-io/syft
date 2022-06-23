package java

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/anchore/syft/syft/source"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

type scaffolding uint8

const (
	mavenScaffolding scaffolding = iota + 1
	gradleScaffolding
)

type scaffoldingParseOptions struct {
	mode string
}

func parseJavaScaffolding(in scaffolding, opts scaffoldingParseOptions) common.RawParserFn {
	return func(loc source.Location, r io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
		var parser, err = newJavaScaffoldingParser(loc, r, opts)
		if err != nil {
			return nil, nil, err
		}
		return parser.parse(in)
	}
}

func newJavaScaffoldingParser(location source.Location, reader io.Reader, options scaffoldingParseOptions) (*scaffoldingParser, error) {
	return &scaffoldingParser{
		currentFilepath: string(location.VisibleRealPath()),
		currentDirpath:  filepath.Dir(string(location.VisibleRealPath())),
		reader:          reader,
		options:         options,
	}, nil
}

type scaffoldingParser struct {
	currentFilepath string
	currentDirpath  string
	reader          io.Reader
	options         scaffoldingParseOptions
}

func (p *scaffoldingParser) parse(target scaffolding) ([]*pkg.Package, []artifact.Relationship, error) {
	var ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var (
		pkgs          []*pkg.Package
		relationships []artifact.Relationship
	)
	switch target {
	default:
		return nil, nil, errors.New("unknown scaffolding")
	case mavenScaffolding:
		if strings.Contains(p.currentDirpath, "/target/META-INF/") {
			// temporary build directory
			return nil, nil, nil
		}
		_, err := os.Stat(filepath.Join(filepath.Dir(p.currentDirpath), "pom.xml"))
		if err == nil {
			// NB(thxCode): since parent project can take over the full transitive dependencies,
			// we can ignore child projects.
			return nil, nil, nil
		}
		pkgs, relationships, err = p.parseMaven(ctx)
		if err != nil {
			return nil, nil, err
		}
	case gradleScaffolding:
		_, err := os.Stat(filepath.Join(filepath.Dir(p.currentDirpath), "build.gradle"))
		if err == nil {
			// NB(thxCode): since parent project can take over the full transitive dependencies,
			// we can ignore child projects.
			return nil, nil, nil
		}
		pkgs, relationships, err = p.parseGradle(ctx)
		if err != nil {
			return nil, nil, err
		}
	}

	for _, pg := range pkgs {
		addPURL(pg)
	}

	return pkgs, relationships, nil
}

func (p *scaffoldingParser) parseMaven(ctx context.Context) (pkgs []*pkg.Package, relationships []artifact.Relationship, berr error) {
	// fetch main pkg
	var mainPkgPomProject, err = parsePomXML(p.currentFilepath, p.reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing pom xml: %w", err)
	}
	var mainPkg = &pkg.Package{
		Name:         mainPkgPomProject.Name,
		Version:      mainPkgPomProject.Version,
		Language:     pkg.Java,
		Type:         pkg.JavaPkg,
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			VirtualPath: p.currentDirpath,
			PomProject:  mainPkgPomProject,
		},
	}

	// fetch pkgs from all groups
	var cmdName = "mvn"
	var dependenciesCmdArgs = "org.apache.maven.plugins:maven-dependency-plugin:3.3.0:tree -DoutputType=txt -DappendOutput=true --fail-fast"
	switch p.options.mode {
	case "offline":
		dependenciesCmdArgs += " --offline"
	case "online", "":
	}
	dependenciesCmdOutputFile, err := ioutil.TempFile("", uuid.NewString())
	if err != nil {
		return nil, nil, fmt.Errorf("error creating maven transitive dependencies output file: %w", err)
	}
	defer func() {
		_ = dependenciesCmdOutputFile.Close()           // close
		_ = os.Remove(dependenciesCmdOutputFile.Name()) // remove
	}()
	dependenciesCmdArgs += " -DoutputFile=" + dependenciesCmdOutputFile.Name()
	dependenciesCmd, err := newCommand(ctx, cmdName, strings.Split(dependenciesCmdArgs, " ")...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating maven transitive dependencies discovery: %w", err)
	}
	dependenciesCmd.Dir = p.currentDirpath
	err = dependenciesCmd.Run()
	if err != nil {
		return nil, nil, fmt.Errorf("error running maven transitive dependencies discovery: %w", err)
	}

	var dependenciesCmdOutputScanner = bufio.NewScanner(dependenciesCmdOutputFile)
	for dependenciesCmdOutputScanner.Scan() {
		// process
		var rough = dependenciesCmdOutputScanner.Text()
		if len(rough) <= 0 {
			continue
		}
		var roughInterestedIdx = strings.Index(rough, "- ")
		if roughInterestedIdx == -1 {
			continue
		}
		var accurate = strings.TrimSpace(rough[roughInterestedIdx+2:])
		var gapvs = strings.Split(accurate, ":") // group:artifact:package-type:version:scope
		if len(gapvs) < 4 {
			continue
		}
		// construct
		var childPkgPomProperties = pkg.PomProperties{
			GroupID:    gapvs[0],
			ArtifactID: gapvs[1],
			Version:    gapvs[3],
			Name:       gapvs[1],
		}
		var childPkg = newPackageFromMavenData(childPkgPomProperties, nil, mainPkg, p.currentDirpath)
		pkgs = append(pkgs, childPkg)
	}

	return pkgs, nil, nil
}

func (p *scaffoldingParser) parseGradle(ctx context.Context) (pkgs []*pkg.Package, relationships []artifact.Relationship, berr error) {
	var cmdName = "gradle"

	// fetch groups and main pkg
	var projects []string
	var isChildPkg bool
	var mainPkgPomProperties = &pkg.PomProperties{}
	var propertiesCmdArgs = ":properties --quiet --no-daemon --console=plain --offline"
	var propertiesCmd, err = newCommand(ctx, cmdName, strings.Split(propertiesCmdArgs, " ")...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating gradle properties discovery: %w", err)
	}
	propertiesCmd.Dir = p.currentDirpath
	propertiesCmdOutput, err := propertiesCmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("error running gradle properties discovery: %w", err)
	}
	var propertiesCmdOutputScanner = bufio.NewScanner(bytes.NewBuffer(propertiesCmdOutput))
	for propertiesCmdOutputScanner.Scan() && !isChildPkg {
		var line = propertiesCmdOutputScanner.Text()
		var cols = strings.SplitN(line, ":", 2)
		switch cols[0] {
		default:
			continue
		case "parent":
			var parentStr = strings.TrimSpace(cols[1])
			isChildPkg = parentStr != "null"
		case "group":
			var groupStr = strings.TrimSpace(cols[1])
			mainPkgPomProperties.GroupID = groupStr
		case "name":
			var nameStr = strings.TrimSpace(cols[1])
			mainPkgPomProperties.Name = nameStr
			mainPkgPomProperties.ArtifactID = nameStr
		case "version":
			var versionStr = strings.TrimSpace(cols[1])
			if versionStr == "unspecified" {
				versionStr = ""
			}
			mainPkgPomProperties.Version = versionStr
		case "subprojects":
			var subprojectsStr = strings.TrimSpace(cols[1])
			if subprojectsStr[0] == '[' && subprojectsStr[len(subprojectsStr)-1] == ']' {
				subprojectsStr = subprojectsStr[1 : len(subprojectsStr)-1]
			}
			var subprojects = strings.Split(subprojectsStr, ", ")
			for i := range subprojects {
				var subproject = subprojects[i]
				subproject = strings.TrimPrefix(subproject, "project ")
				if subproject[0] == '\'' && subproject[len(subproject)-1] == '\'' {
					subproject = subproject[1 : len(subproject)-1]
				}
				projects = append(projects, subproject)
			}
		}
	}
	if isChildPkg {
		return nil, nil, nil
	}
	var mainPkg = &pkg.Package{
		Name:         mainPkgPomProperties.Name,
		Version:      mainPkgPomProperties.Version,
		Language:     pkg.Java,
		Type:         pkg.JavaPkg,
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			VirtualPath:   p.currentDirpath,
			PomProperties: mainPkgPomProperties,
		},
	}

	// fetch pkgs from all groups
	for i := range projects {
		var project = projects[i]
		// NB(thxCode): choose `testRuntimeClasspath` as the only configuration,
		// ref to https://tomgregory.com/gradle-implementation-vs-compile-dependencies/.
		var dependenciesCmdArgs = project + ":dependencies --quiet --no-daemon --console=plain --configuration=testRuntimeClasspath"
		switch p.options.mode {
		case "offline":
			dependenciesCmdArgs += " --offline"
		case "online", "":
		}
		var dependenciesCmd, err = newCommand(ctx, cmdName, strings.Split(dependenciesCmdArgs, " ")...)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating gradle transitive dependencies discovery: %w", err)
		}
		dependenciesCmd.Dir = p.currentDirpath
		dependenciesCmdOutput, err := dependenciesCmd.CombinedOutput()
		if err != nil {
			return nil, nil, fmt.Errorf("error running gradle transitive dependencies discovery: %w", err)
		}
		var dependenciesCmdOutputScanner = bufio.NewScanner(bytes.NewBuffer(dependenciesCmdOutput))
		for dependenciesCmdOutputScanner.Scan() {
			var rough = dependenciesCmdOutputScanner.Text()
			if len(rough) <= 3 {
				continue
			}
			switch rough[len(rough)-3:] {
			case "(n)", "(*)":
				continue
			default:
			}
			var roughInterestedIdx = strings.Index(rough, "--- ")
			if roughInterestedIdx == -1 {
				continue
			}
			var accurate = strings.TrimSpace(rough[roughInterestedIdx+4:])
			accurate = strings.TrimSuffix(accurate, " FAILED") // for offline
			var accurateIgnoredIdx = strings.LastIndex(accurate, " -> ")
			if accurateIgnoredIdx != -1 {
				continue
			}
			var gav = strings.SplitN(accurate, ":", 3) // group:artifact:version
			if len(gav) != 3 {
				continue
			}
			// construct
			var childPkgPomProperties = pkg.PomProperties{
				GroupID:    gav[0],
				ArtifactID: gav[1],
				Version:    gav[2],
				Name:       gav[1],
			}
			var childPkg = newPackageFromMavenData(childPkgPomProperties, nil, mainPkg, p.currentDirpath)
			pkgs = append(pkgs, childPkg)
		}
	}

	return pkgs, nil, nil
}

func newCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	var binpath, err = exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s is required for runtime: %w", name, err)
	}
	var cmd = exec.CommandContext(ctx, binpath, args...)
	return cmd, nil
}
