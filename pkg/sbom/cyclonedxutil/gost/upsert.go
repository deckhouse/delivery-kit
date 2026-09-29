package gost

import (
	"fmt"
	"maps"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

// Upsert inserts or updates mandatory GOST properties in the BOM metadata component
// and every component, nested ones included. An attack surface of `yes` describes
// the components an attacker reaches directly, so it lands on the roots of the
// dependency tree; everything pulled in by another component gets `indirect`.
// Every other value, and the security function in all cases, applies unchanged.
func Upsert(bom *cdx.BOM, config Config) error {
	if bom == nil {
		return fmt.Errorf("BOM is required")
	}

	dependencyConfig := config
	if config.AttackSurface == GostValueYes {
		dependencyConfig.AttackSurface = GostValueIndirect
	}

	targets := dependencyTargets(bom)

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		SetComponent(bom.Metadata.Component, config)
		setComponents(lo.FromPtr(bom.Metadata.Component.Components), config, dependencyConfig, targets)
	}

	setComponents(lo.FromPtr(bom.Components), config, dependencyConfig, targets)

	return nil
}

func setComponents(components []cdx.Component, rootConfig, dependencyConfig Config, targets map[string]struct{}) {
	for i := range components {
		comp := &components[i]

		cfg := rootConfig
		if _, ok := targets[comp.BOMRef]; ok {
			cfg = dependencyConfig
		}

		SetComponent(comp, cfg)
		setComponents(lo.FromPtr(comp.Components), rootConfig, dependencyConfig, targets)
	}
}

// dependencyTargets collects every bom-ref some root of the dependency tree
// pulls in, directly or through other components. A component missing from the
// set is a root: nothing else in the image depends on it. An empty
// `dependencies` section therefore makes every component a root, which is what
// the catalogers that report no tree at all produce.
//
// Roots are found per strongly connected component rather than per node: OS
// package graphs contain mutual dependencies (libc and libgcc depend on each
// other), and counting in-edges alone would leave such a cycle with no root
// even when nothing outside of it depends on it.
//
// Only edges sourced at a component count. An edge from the scanned image's
// own metadata component describes what the image contains, not what one
// package pulls in, and honoring it would leave the tree without a single root;
// an edge from a service describes what the service uses, and a package is not
// pulled in by the service that calls it.
func dependencyTargets(bom *cdx.BOM) map[string]struct{} {
	componentRefs := make(map[string]struct{})
	collectComponentRefs(lo.FromPtr(bom.Components), componentRefs)
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		collectComponentRefs(lo.FromPtr(bom.Metadata.Component.Components), componentRefs)
	}

	edges := make(map[string][]string)
	for _, dep := range lo.FromPtr(bom.Dependencies) {
		if _, ok := componentRefs[dep.Ref]; !ok {
			continue
		}

		edges[dep.Ref] = append(edges[dep.Ref], lo.FromPtr(dep.Dependencies)...)
	}

	componentOf := stronglyConnectedComponents(edges)

	dependedOn := make(map[int]struct{})
	for from, tos := range edges {
		for _, to := range tos {
			if componentOf[from] != componentOf[to] {
				dependedOn[componentOf[to]] = struct{}{}
			}
		}
	}

	targets := make(map[string]struct{})
	for ref, component := range componentOf {
		if _, ok := dependedOn[component]; ok {
			targets[ref] = struct{}{}
		}
	}

	return targets
}

func collectComponentRefs(components []cdx.Component, refs map[string]struct{}) {
	for i := range components {
		if components[i].BOMRef != "" {
			refs[components[i].BOMRef] = struct{}{}
		}
		collectComponentRefs(lo.FromPtr(components[i].Components), refs)
	}
}

// stronglyConnectedComponents runs Tarjan's algorithm over the adjacency list
// and labels every node with the index of its component.
func stronglyConnectedComponents(edges map[string][]string) map[string]int {
	t := &tarjan{
		edges:       edges,
		index:       make(map[string]int),
		lowlink:     make(map[string]int),
		onStack:     make(map[string]bool),
		componentOf: make(map[string]int),
	}

	for _, node := range slices.Sorted(maps.Keys(edges)) {
		if _, seen := t.index[node]; !seen {
			t.visit(node)
		}
	}

	return t.componentOf
}

type tarjan struct {
	edges         map[string][]string
	index         map[string]int
	lowlink       map[string]int
	onStack       map[string]bool
	componentOf   map[string]int
	stack         []string
	nextIndex     int
	nextComponent int
}

func (t *tarjan) visit(node string) {
	t.index[node] = t.nextIndex
	t.lowlink[node] = t.nextIndex
	t.nextIndex++
	t.stack = append(t.stack, node)
	t.onStack[node] = true

	for _, next := range t.edges[node] {
		if _, seen := t.index[next]; !seen {
			t.visit(next)
			t.lowlink[node] = min(t.lowlink[node], t.lowlink[next])
		} else if t.onStack[next] {
			t.lowlink[node] = min(t.lowlink[node], t.index[next])
		}
	}

	if t.lowlink[node] == t.index[node] {
		t.popComponent(node)
	}
}

func (t *tarjan) popComponent(root string) {
	for {
		top := t.stack[len(t.stack)-1]
		t.stack = t.stack[:len(t.stack)-1]
		t.onStack[top] = false
		t.componentOf[top] = t.nextComponent
		if top == root {
			break
		}
	}
	t.nextComponent++
}

// SetComponent inserts or updates mandatory GOST properties in a single component.
func SetComponent(comp *cdx.Component, config Config) {
	a := newAccessor(comp)
	a.SetAttackSurface(config.AttackSurface)
	a.SetSecurityFunction(config.SecurityFunction)
}

func GetComponent(comp *cdx.Component) Config {
	a := newAccessor(comp)
	attack, _ := a.GetAttackSurface()
	security, _ := a.GetSecurityFunction()
	return Config{
		AttackSurface:    attack,
		SecurityFunction: security,
	}
}
