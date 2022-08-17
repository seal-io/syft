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
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/anchore/syft/syft/pkg/cataloger/common/command"
	"github.com/anchore/syft/syft/source"
)

const (
	GoSumFileName = "go.sum"
	GoCommand     = "go"
)

func scaffoldingParserFn(src *source.Source) common.RawParserFn {
	return func(loc source.Location, r io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
		currentFilepath := string(loc.VisibleRealPath())
		parser := scaffoldingGoModuleParser{
			currentFilepath:  currentFilepath,
			relativeFilePath: loc.Coordinates.RealPath,
			currentFileDir:   filepath.Dir(currentFilepath),
			command:          GoCommand,
			reader:           r,
			source:           src,
		}
		return parser.parse()
	}
}

type scaffoldingGoModuleParser struct {
	currentFilepath  string
	relativeFilePath string
	currentFileDir   string
	command          string
	reader           io.Reader
	source           *source.Source
}

func (p *scaffoldingGoModuleParser) parse() ([]*pkg.Package, []artifact.Relationship, error) {
	// lock file isn't existed, fall back to parse go.mod
	if _, err := os.Stat(filepath.Join(filepath.Dir(p.currentFilepath), GoSumFileName)); err != nil {
		return parseGoMod(p.currentFilepath, p.reader)
	}

	log.Infof("parsing dependency file %s by scaffolding", p.currentFilepath)
	var ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Info("parsing current module for %s", p.currentFilepath)
	curModule, curPkg, curRelation, err := p.parseCurrentFileModule(ctx)
	if err != nil {
		return nil, nil, err
	}

	log.Info("parsing all modules for %s", p.currentFilepath)
	moduleMap, err := p.parseAllModules(ctx)
	if err != nil {
		return nil, nil, err
	}

	filteredModules, pkgs, err := p.filterModules(ctx, moduleMap, curModule, curPkg)
	if err != nil {
		return nil, nil, err
	}

	log.Info("generating dependency tree for %s", p.currentFilepath)
	relationships, err := p.parseModuleRelationships(ctx, curModule, curPkg, curRelation, filteredModules)
	if err != nil {
		return nil, nil, err
	}

	log.Infof("finished parsing dependency file %s, found %d packages, %d relationships", p.currentFilepath, len(pkgs), len(relationships))
	return pkgs, relationships, nil
}

func (p *scaffoldingGoModuleParser) parseCurrentFileModule(ctx context.Context) (*Module, *pkg.Package, *artifact.Relationship, error) {
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

	from, err := pkg.FileToPackage(p.source.Metadata.Path)
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

func (p *scaffoldingGoModuleParser) parseAllModules(ctx context.Context) (modules map[string]*Module, err error) {
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

func (p *scaffoldingGoModuleParser) filterModules(ctx context.Context, moduleMap map[string]*Module, curModule *Module, curPkg *pkg.Package) ([]*Module, []*pkg.Package, error) {
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
	var pkgs = []*pkg.Package{curPkg}
	for _, v := range moduleMap {
		if ps, ok := moduleWhyPkgs[v.Path]; ok && len(ps) != 0 {
			filteredModules = append(filteredModules, v)
			// skip main since we already append curPkg to pkgs
			if v.Main {
				continue
			}
			pkgs = append(pkgs, moduleToPackage(curModule, v))
		}
	}

	return filteredModules, pkgs, nil
}

func (p *scaffoldingGoModuleParser) parseModuleRelationships(
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

func (p *scaffoldingGoModuleParser) runGetCurrentModule(ctx context.Context) (io.Reader, error) {
	// go list -mod readonly -json -m
	args := "list -mod readonly -json -m"
	return command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
}

func (p *scaffoldingGoModuleParser) runListAllModules(ctx context.Context) (io.Reader, error) {
	// go list -mod readonly -json -m
	args := "list -mod readonly -json -m all"
	return command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
}

func (p *scaffoldingGoModuleParser) runListRelationship(ctx context.Context) (io.Reader, error) {
	// go mod graph
	args := "mod graph"
	return command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
}

func (p *scaffoldingGoModuleParser) runModuleWhy(ctx context.Context) (io.Reader, error) {
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
