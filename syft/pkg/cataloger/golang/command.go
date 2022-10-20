package golang

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/command"
)

const (
	GoCommand = "go"
)

type commandRunner struct {
	command        string
	currentFileDir string
}

func newRunner(currentFileDir string) *commandRunner {
	return &commandRunner{
		command:        GoCommand,
		currentFileDir: currentFileDir,
	}
}

func (p *commandRunner) listAllModules(ctx context.Context) (modules map[string]*pkg.Module, err error) {
	buf, err := p.runListAllModules(ctx)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(buf)
	for decoder.More() {
		m := &pkg.Module{}
		if err = decoder.Decode(m); err != nil {
			return nil, fmt.Errorf("failed to decode result from list all modules, %w", err)
		}

		if modules == nil {
			modules = make(map[string]*pkg.Module)
		}
		modules[m.Path] = m
	}

	return modules, nil
}

func (p *commandRunner) getCurrentModule(ctx context.Context) (*pkg.Module, error) {
	buf, err := p.runGetCurrentModule(ctx)
	if err != nil {
		return nil, err
	}

	m := pkg.Module{}
	decoder := json.NewDecoder(buf)
	if err = decoder.Decode(&m); err != nil {
		return nil, fmt.Errorf("failed to decode result from get root module, %w", err)
	}
	return &m, nil
}

// getReleaseTime get the version release time
func (p *commandRunner) getModuleByName(ctx context.Context, depName, version string) (*pkg.Module, error) {
	// go list -json -m ${depName}
	args := fmt.Sprintf("list -json -m %s@%s", depName, version)
	buf, err := command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
	if err != nil {
		return nil, err
	}

	m := pkg.Module{}
	decoder := json.NewDecoder(buf)
	if err = decoder.Decode(&m); err != nil {
		return nil, err
	}

	return &m, nil
}

// addModule add the dependency to the dependency file and download it
func (p *commandRunner) addModule(ctx context.Context, depName, version string) error {
	// go get ${packageName}@{version}
	args := fmt.Sprintf("get %s@%s", depName, version)
	_, err := command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
	if err != nil {
		return fmt.Errorf("failed to down dependency %s@%s:%w", depName, version, err)
	}
	return nil
}

func (p *commandRunner) getWhyModules(ctx context.Context) (map[string][]string, error) {
	buf, err := p.runWhyModules(ctx)
	if err != nil {
		return nil, err
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
	return moduleWhyPkgs, nil
}

// listModuleVersions list all versions for module
func (p *commandRunner) listModuleVersions(ctx context.Context, depName string) ([]string, error) {
	// go list -versions -json -m ${depName}
	args := fmt.Sprintf("list -versions -json -m %s", depName)
	buf, err := command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
	if err != nil {
		return nil, err
	}

	m := pkg.Module{}
	decoder := json.NewDecoder(buf)
	if err = decoder.Decode(&m); err != nil {
		return nil, err
	}
	return m.Versions, nil
}

// tidy update the dependency file
func (p *commandRunner) tidy(ctx context.Context) error {
	// go mod tidy
	args := "mod tidy"
	_, err := command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
	if err != nil {
		return fmt.Errorf("failed to update dependency file: %w", err)
	}
	return nil
}

func (p *commandRunner) runGetCurrentModule(ctx context.Context) (io.Reader, error) {
	// go list -mod readonly -json -m
	args := "list -mod readonly -json -m"
	return command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
}

func (p *commandRunner) runListAllModules(ctx context.Context) (io.Reader, error) {
	// go list -mod readonly -json -m
	args := "list -mod readonly -json -m all"
	return command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
}

func (p *commandRunner) runListRelationship(ctx context.Context) (io.Reader, error) {
	// go mod graph
	args := "mod graph"
	return command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
}

func (p *commandRunner) runWhyModules(ctx context.Context) (io.Reader, error) {
	// go mod why -vendor -m all
	args := "mod why -vendor -m all"
	return command.RunCommand(ctx, p.command, p.currentFileDir, strings.Split(args, " ")...)
}
