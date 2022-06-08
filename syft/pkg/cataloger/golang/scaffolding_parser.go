package golang

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common/command"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

func scaffoldingParser() generic.Parser {
	return func(fileResolver source.FileResolver, environment *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
		var currentFilepath = string(reader.VisibleRealPath())
		var p = goModScaffoldingParser{
			fileResolver:     fileResolver,
			environment:      environment,
			reader:           reader,
			currentFilepath:  currentFilepath,
			currentFileDir:   filepath.Dir(currentFilepath),
			relativeFilePath: reader.Coordinates.RealPath,
			relativeFileDir:  fileResolver.RootPath(),
			command:          "go",
		}
		return p.parse()
	}
}

type goModScaffoldingParser struct {
	fileResolver     source.FileResolver
	environment      *generic.Environment
	reader           source.LocationReadCloser
	currentFilepath  string
	currentFileDir   string
	relativeFilePath string
	relativeFileDir  string
	command          string
}

// nolint: nolintlint,nakedret
func (p *goModScaffoldingParser) parse() (pkgs []pkg.Package, relationships []artifact.Relationship, err error) {
	// lock file isn't existed, fall back to parse go.mod
	defer func() {
		if err != nil {
			log.Warnf("failed in scaffolding go module parse, file %s, fall back to parse go.mod: %v", p.relativeFilePath, err)
			pkgs, relationships, err = parseGoModFile(p.fileResolver, p.environment, p.reader)
		}
		if len(pkgs) != 0 {
			log.Infof("finished parsing golang dependency file %s, found %d packages", p.relativeFilePath, len(pkgs))
		}
	}()

	if _, err = os.Stat(filepath.Join(filepath.Dir(p.currentFilepath), "go.sum")); err != nil {
		return
	}

	log.Infof("parsing dependency file %s by scaffolding", p.currentFilepath)
	var ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Info("parsing current module for %s", p.currentFilepath)
	var (
		curModule   *Module
		curPkg      *pkg.Package
		curRelation *artifact.Relationship
	)
	curModule, curPkg, curRelation, err = p.parseCurrentFileModule(ctx)
	if err != nil {
		return
	}

	log.Info("parsing all modules for %s", p.currentFilepath)
	var moduleMap map[string]*Module
	moduleMap, err = p.parseAllModules(ctx)
	if err != nil {
		return nil, nil, err
	}

	var filteredModules []*Module
	filteredModules, pkgs, err = p.filterModules(ctx, moduleMap, curModule, curPkg)
	if err != nil {
		return
	}

	log.Info("generating dependency tree for %s", p.currentFilepath)
	relationships, err = p.parseModuleRelationships(ctx, curModule, curPkg, curRelation, filteredModules)
	if err != nil {
		return
	}

	log.Infof("finished parsing dependency file %s, found %d packages, %d relationships", p.currentFilepath, len(pkgs), len(relationships))
	return
}

func (p *goModScaffoldingParser) parseCurrentFileModule(ctx context.Context) (*Module, *pkg.Package, *artifact.Relationship, error) {
	buf, err := p.runGetCurrentModule(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	m := Module{}
	decoder := json.NewDecoder(buf)
	if err = decoder.Decode(&m); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode result from get root module, %w", err)
	}

	to, err := pkg.FileToPackage(p.relativeFilePath)
	if err != nil {
		return nil, nil, nil, err
	}

	from, err := pkg.FileToPackage(p.relativeFileDir)
	if err != nil {
		return nil, nil, nil, err
	}

	relation := &artifact.Relationship{
		From: from,
		To:   to,
		Type: artifact.DependencyOfRelationship,
	}

	return &m, to, relation, nil
}

func (p *goModScaffoldingParser) parseAllModules(ctx context.Context) (modules map[string]*Module, err error) {
	buf, err := p.runListAllModules(ctx)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(buf)
	for decoder.More() {
		m := &Module{}
		if err = decoder.Decode(m); err != nil {
			return nil, fmt.Errorf("failed to decode result from list all modules, %w", err)
		}

		if modules == nil {
			modules = make(map[string]*Module)
		}

		if _, ok := modules[m.Path]; ok {
			fmt.Println("already exited")
		}
		modules[m.Path] = m
	}

	return modules, nil
}

func (p *goModScaffoldingParser) filterModules(ctx context.Context, moduleMap map[string]*Module, curModule *Module, curPkg *pkg.Package) ([]*Module, []pkg.Package, error) {
	buf, err := p.runModuleWhy(ctx)
	if err != nil {
		return nil, nil, err
	}

	var currentModule string
	var moduleWhyPkgs = make(map[string][]string)
	var scanner = bufio.NewScanner(buf)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "(main module does not need") {
			continue
		}

		if strings.HasPrefix(line, "#") {
			currentModule = strings.TrimPrefix(line, "# ")
			moduleWhyPkgs[currentModule] = make([]string, 0)
			continue
		}

		moduleWhyPkgs[currentModule] = append(moduleWhyPkgs[currentModule], line)
	}

	var filteredModules []*Module
	var pkgs = []pkg.Package{*curPkg}
	for _, v := range moduleMap {
		if ps, ok := moduleWhyPkgs[v.Path]; ok && len(ps) != 0 {
			filteredModules = append(filteredModules, v)
			// skip main since we already append curPkg to pkgs
			if v.Main {
				continue
			}
			pkgs = append(pkgs, *moduleToPackage(curModule, v))
		}
	}

	return filteredModules, pkgs, nil
}

func (p *goModScaffoldingParser) parseModuleRelationships(
	ctx context.Context,
	curModule *Module,
	curPkg *pkg.Package,
	relation *artifact.Relationship,
	modules []*Module,
) (relationships []artifact.Relationship, err error) {
	relationships = append(relationships, *relation)
	buf, err := p.runListRelationship(ctx)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) != 2 {
			log.Warn("invalid go mod dependency relationship %s", scanner.Text())
			continue
		}

		from := fields[0]
		to := fields[1]
		fromModule := findModule(modules, from, true)
		if fromModule == nil {
			continue
		}

		// Go's use minimal version selection strategy to decide final used version, when packages in project depends on multiple version.
		// But in go mod graph, may show the relation with older version, the replaced final version may not present,
		// so we query with non-strict mode.
		toModule := findModule(modules, to, false)
		if toModule == nil {
			continue
		}

		// overwrite current module with mod file
		fromPkg := moduleToPackage(curModule, fromModule)
		if fromModule.Path == curModule.Path && fromModule.Version == curModule.Version {
			fromPkg = curPkg
		}

		toPkg := moduleToPackage(curModule, toModule)
		relation := artifact.Relationship{
			From: fromPkg,
			To:   toPkg,
			Type: artifact.DependencyOfRelationship,
		}

		relationships = append(relationships, relation)
	}
	return relationships, nil
}

func (p *goModScaffoldingParser) runGetCurrentModule(ctx context.Context) (io.Reader, error) {
	// go list -mod readonly -json -m
	args := "list -mod readonly -json -m"
	return command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
}

func (p *goModScaffoldingParser) runListAllModules(ctx context.Context) (io.Reader, error) {
	// go list -mod readonly -json -m
	args := "list -mod readonly -json -m all"
	return command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
}

func (p *goModScaffoldingParser) runListRelationship(ctx context.Context) (io.Reader, error) {
	// go mod graph
	args := "mod graph"
	return command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
}

func (p *goModScaffoldingParser) runModuleWhy(ctx context.Context) (io.Reader, error) {
	// go mod why -vendor -m all
	args := "mod why -vendor -m all"
	return command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
}

func moduleToPackage(curModule, module *Module) *pkg.Package {
	p := &pkg.Package{
		Name:     module.Path,
		Version:  module.Version,
		Language: pkg.Go,
		Type:     pkg.GoModulePkg,
	}

	if module.Replace != nil {
		if strings.HasPrefix(module.Replace.Path, "./") || strings.HasPrefix(module.Replace.Path, "../") {
			// relative path will be omitted in go list output, but will show v0.0.0 in go mod graph output
			// https://go.dev/ref/mod#go-mod-file-replace
			p.Version = "v0.0.0"
			p.Name = filepath.Join(curModule.Path, module.Replace.Path)
		} else {
			p.Name = module.Replace.Path
			p.Version = module.Replace.Version
		}
	}

	p.SetID()
	return p
}
