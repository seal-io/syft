package java

import (
	"bufio"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

type parseLine func(line string) (level int, pkg *pkg.Package, err error)

type isLineValid func(line string) (valid bool)

// parseGraph is a common framework to get packages and relationships from dependency tree
// example:
// +--- org.apache.commons:commons-math3:3.6.1
// +--- com.google.guava:guava:30.1.1-jre
// |    +--- com.google.guava:failureaccess:1.0.1
// |    \--- com.google.j2objc:j2objc-annotations:1.3
// +--- org.apache.logging.log4j:log4j-core:2.12.0
// |    \--- org.apache.logging.log4j:log4j-api:2.12.0
// \--- junit:junit:4.13.2
// \--- org.hamcrest:hamcrest-core:1.3
func parseGraph(scanner *bufio.Scanner, isLineValid isLineValid, parser parseLine) (directlyDependencies, pkgs []*pkg.Package, relationships []artifact.Relationship, err error) {
	var parents []*pkg.Package
	for scanner.Scan() {
		var line = scanner.Text()

		if ok := isLineValid(line); !ok {
			continue
		}

		level, child, err := parser(line)
		if err != nil {
			return nil, nil, nil, err
		}

		if len(parents) >= level {
			parents = parents[:level-1]
		}

		if level == 1 {
			directlyDependencies = append(directlyDependencies, child)
		} else {
			parent := parents[len(parents)-1]
			var fromID = &PackageURL{Package: *parent}
			var toID = &PackageURL{Package: *child}
			relation := artifact.Relationship{
				From: fromID,
				To:   toID,
				Type: artifact.DependencyOfRelationship,
			}

			relationships = append(relationships, relation)
		}
		parents = append(parents, child)
		pkgs = append(pkgs, child)
	}

	return directlyDependencies, pkgs, relationships, nil
}
