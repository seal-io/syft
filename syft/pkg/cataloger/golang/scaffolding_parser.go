package golang

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/anchore/syft/syft/source"
)

const (
	GoSumFileName = "go.sum"
)

func scaffoldingParserFn(src *source.Source) common.RawParserFn {
	return func(loc source.Location, r io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
		currentFilepath := string(loc.VisibleRealPath())
		parser := scaffoldingGoModuleParser{
			currentFilepath:  currentFilepath,
			relativeFilePath: loc.Coordinates.RealPath,
			reader:           r,
			source:           src,
			runner:           newRunner(filepath.Dir(currentFilepath)),
		}
		return parser.parse()
	}
}

type scaffoldingGoModuleParser struct {
	currentFilepath  string
	relativeFilePath string
	reader           io.Reader
	source           *source.Source
	runner           *commandRunner
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
	moduleMap, err := p.runner.listAllModules(ctx)
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

func (p *scaffoldingGoModuleParser) parseCurrentFileModule(ctx context.Context) (*pkg.Module, *pkg.Package, *artifact.Relationship, error) {
	m, err := p.runner.getCurrentModule(ctx)
	if err != nil {
		return nil, nil, nil, err
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

	return m, to, relation, nil
}

func (p *scaffoldingGoModuleParser) filterModules(ctx context.Context, moduleMap map[string]*pkg.Module, curModule *pkg.Module, curPkg *pkg.Package) ([]*pkg.Module, []*pkg.Package, error) {
	moduleWhyPkgs, err := p.runner.getWhyModules(ctx)
	if err != nil {
		return nil, nil, err
	}

	var filteredModules []*pkg.Module
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
	curModule *pkg.Module,
	curPkg *pkg.Package,
	relation *artifact.Relationship,
	modules []*pkg.Module,
) (relationships []artifact.Relationship, err error) {

	relationships = append(relationships, *relation)
	buf, err := p.runner.runListRelationship(ctx)
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
		fromModule := pkg.FindModule(modules, from, true)
		if fromModule == nil {
			continue
		}

		// Go's use minimal version selection strategy to decide final used version, when packages in project depends on multiple version.
		// But in go mod graph, may show the relation with older version, the replaced final version may not present,
		// so we query with non-strict mode.
		toModule := pkg.FindModule(modules, to, false)
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

func moduleToPackage(curModule, module *pkg.Module) *pkg.Package {
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
