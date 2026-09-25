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
// Edges sourced at the scanned image's own metadata component are skipped: a
// cataloger that lists every package under the image root describes what the
// image contains, not what one package pulls in, and honoring those edges would
// leave the tree without a single root.
func dependencyTargets(bom *cdx.BOM) map[string]struct{} {
	var rootRef string
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		rootRef = bom.Metadata.Component.BOMRef
	}

	edges := make(map[string][]string)
	for _, dep := range lo.FromPtr(bom.Dependencies) {
		if rootRef != "" && dep.Ref == rootRef {
			continue
		}

		for _, ref := range lo.FromPtr(dep.Dependencies) {
			if ref != dep.Ref {
				edges[dep.Ref] = append(edges[dep.Ref], ref)
			}
		}
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

// stronglyConnectedComponents runs Tarjan's algorithm over the adjacency list
// and labels every node with the index of its component.
func stronglyConnectedComponents(edges map[string][]string) map[string]int {
	index := make(map[string]int)
	lowlink := make(map[string]int)
	onStack := make(map[string]bool)
	componentOf := make(map[string]int)
	var stack []string
	nextIndex, nextComponent := 0, 0

	var visit func(node string)
	visit = func(node string) {
		index[node] = nextIndex
		lowlink[node] = nextIndex
		nextIndex++
		stack = append(stack, node)
		onStack[node] = true

		for _, next := range edges[node] {
			if _, seen := index[next]; !seen {
				visit(next)
				lowlink[node] = min(lowlink[node], lowlink[next])
			} else if onStack[next] {
				lowlink[node] = min(lowlink[node], index[next])
			}
		}

		if lowlink[node] != index[node] {
			return
		}

		for {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[top] = false
			componentOf[top] = nextComponent
			if top == node {
				break
			}
		}
		nextComponent++
	}

	for _, node := range slices.Sorted(maps.Keys(edges)) {
		if _, seen := index[node]; !seen {
			visit(node)
		}
	}

	return componentOf
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
