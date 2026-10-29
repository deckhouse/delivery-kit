package nativegate

import (
	"context"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/werf/werf/v3/pkg/build/import_server"
	"github.com/werf/werf/v3/pkg/path_matcher"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// ImportBackend is the copy an import is applied with. The native builders walk the
// source subtree themselves, the legacy Stapel builder pulls it over rsync, and the two
// read the include and exclude paths of the same import differently.
type ImportBackend string

const (
	ImportBackendCopyRecurse ImportBackend = ""
	ImportBackendRsync       ImportBackend = "rsync"
)

// ImportScope is one dependency import as the build applies it.
type ImportScope struct {
	Backend      ImportBackend
	FromPath     string
	ToPath       string
	IncludePaths []string
	ExcludePaths []string
}

// Imports are applied in build order; equal bytes outside this scope confer no binding.
func importOriginalMatches(ctx context.Context, source *shippedscope.FileIndex, matches originalMatches, before, after *shippedscope.FileIndex, scope ImportScope) (originalMatches, error) {
	if source == nil || before == nil || after == nil {
		return nil, fmt.Errorf("no-data: importing original matches needs the source and both target snapshots")
	}
	if source.Incomplete || before.Incomplete || after.Incomplete {
		return nil, fmt.Errorf("no-data: an incomplete snapshot cannot carry original matches across an import")
	}
	if source.Directories == nil || before.Directories == nil || after.Directories == nil {
		return nil, fmt.Errorf("no-data: importing original matches needs directory facts")
	}
	if err := validateSourceMatches(source, matches); err != nil {
		return nil, err
	}

	from, err := importSourcePath(source, scope.FromPath)
	if err != nil {
		return nil, err
	}
	carries, err := importScopeCarries(scope, from)
	if err != nil {
		return nil, err
	}
	if _, ok := source.Symlinks[from]; ok {
		if scope.Backend == ImportBackendRsync {
			// The copy command stats the source through the link and copies what it
			// names, under a scope this gate cannot place on the resolved path.
			return nil, fmt.Errorf("no-data: import source %q is a symlink the rsync copy follows", scope.FromPath)
		}

		// The link itself travels; the bytes it names stay where they are.
		return make(originalMatches), nil
	}

	to, err := importDestinationPath(before, after, scope.ToPath)
	if err != nil {
		return nil, err
	}

	projected, err := projectedImportPaths(source, matches, before, after, from, to, carries)
	if err != nil {
		return nil, err
	}

	imported := make(originalMatches)
	landed := make(map[string]string, len(projected))
	for _, sourcePath := range slices.Sorted(maps.Keys(projected)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		destination := projected[sourcePath]
		if after.Files[destination] != source.Files[sourcePath] {
			continue
		}

		bindings := sortedOriginalBindings(matches[sourcePath])
		if kept, ok := imported[destination]; ok && !slices.Equal(kept, bindings) {
			return nil, fmt.Errorf("no-data: the import lands %q and %q on %q with different originals", landed[destination], sourcePath, destination)
		}
		imported[destination] = bindings
		landed[destination] = sourcePath
	}

	return imported, nil
}

func validateSourceMatches(source *shippedscope.FileIndex, matches originalMatches) error {
	for _, name := range slices.Sorted(maps.Keys(matches)) {
		if _, ok := source.Files[name]; !ok {
			return fmt.Errorf("original match %q is outside the indexed source", name)
		}
		if len(matches[name]) == 0 {
			return fmt.Errorf("original match %q carries no binding", name)
		}
		for _, binding := range matches[name] {
			if binding.Source == "" || binding.Path == "" {
				return fmt.Errorf("original match %q carries an incomplete binding", name)
			}
		}
	}

	return nil
}

// Match the backend's no-follow behavior for the final source component.
func importSourcePath(source *shippedscope.FileIndex, fromPath string) (string, error) {
	from := rootedImportPath(fromPath)
	parent, err := resolvePath(&filesystem{index: source}, path.Dir(from))
	if err != nil {
		return "", fmt.Errorf("no-data: import source %q: %w", fromPath, err)
	}

	return path.Join(parent, path.Base(from)), nil
}

// A changed destination link loses the intermediate path evidence.
func importDestinationPath(before, after *shippedscope.FileIndex, toPath string) (string, error) {
	to, err := resolvePath(&filesystem{index: before}, rootedImportPath(toPath))
	if err != nil {
		return "", fmt.Errorf("no-data: import destination %q: %w", toPath, err)
	}
	ended, err := resolvePath(&filesystem{index: after}, rootedImportPath(toPath))
	if err != nil || ended != to {
		return "", fmt.Errorf("no-data: import destination %q resolves through links the stage changed", toPath)
	}

	return to, nil
}

func projectedImportPaths(source *shippedscope.FileIndex, matches originalMatches, before, after *shippedscope.FileIndex, from, to string, carries func(relative string) bool) (map[string]string, error) {
	if _, ok := source.Files[from]; ok {
		if _, held := matches[from]; !held || !carries(".") {
			return nil, nil
		}

		destination, err := importedFileDestination(before, after, from, to)
		if err != nil {
			return nil, err
		}

		return map[string]string{from: destination}, nil
	}

	if _, ok := source.Directories[from]; !ok {
		return nil, fmt.Errorf("no-data: import source %q is neither a file nor a directory of the source image", from)
	}

	projected := make(map[string]string)
	for sourcePath := range matches {
		relative, ok := pathUnder(from, sourcePath)
		if !ok || !carries(relative) {
			continue
		}

		projected[sourcePath] = path.Join(to, relative)
	}

	return projected, nil
}

// Do not guess file-versus-directory placement from the final snapshot alone.
func importedFileDestination(before, after *shippedscope.FileIndex, from, to string) (string, error) {
	_, wasDirectory := before.Directories[to]
	if _, isDirectory := after.Directories[to]; wasDirectory != isDirectory {
		return "", fmt.Errorf("no-data: the import destination %q is a directory on only one side of the stage", to)
	}
	if wasDirectory {
		return path.Join(to, path.Base(from)), nil
	}

	return to, nil
}

// importScopeCarries answers, for a path of the import source named relative to it,
// whether the copy of this backend carries it. The include and exclude paths of one
// import mean different things to the two backends, and a path the copy leaves behind
// borrows nothing from equal bytes the destination already holds.
func importScopeCarries(scope ImportScope, from string) (func(relative string) bool, error) {
	switch scope.Backend {
	case ImportBackendCopyRecurse:
		matcher := path_matcher.NewPathMatcher(path_matcher.PathMatcherOptions{
			IncludeGlobs: scope.IncludePaths,
			ExcludeGlobs: scope.ExcludePaths,
		})

		return func(relative string) bool {
			if relative == "." {
				return matcher.IsPathMatched(".")
			}

			return copiedByScope(matcher, relative)
		}, nil
	case ImportBackendRsync:
		if len(scope.IncludePaths)+len(scope.ExcludePaths) != 0 && from != rootedImportPath(scope.FromPath) {
			return nil, fmt.Errorf("no-data: the rsync filters of import source %q are written for a path the source image resolves elsewhere", scope.FromPath)
		}
		rules, err := compiledRsyncRules(from, scope)
		if err != nil {
			return nil, err
		}

		return func(relative string) bool {
			return copiedByRsyncRules(rules, from, relative)
		}, nil
	default:
		return nil, fmt.Errorf("no-data: the import scope names the unknown copy backend %q", scope.Backend)
	}
}

// The import root is always walked. Below it a matched directory is copied whole and
// unfiltered — an exclude inside it does not apply — a directory worth going through is
// walked on, and anything else is pruned along with everything beneath it.
func copiedByScope(matcher path_matcher.PathMatcher, relative string) bool {
	parts := strings.Split(relative, "/")
	for n := 1; n < len(parts); n++ {
		directory := strings.Join(parts[:n], "/")
		if matcher.IsPathMatched(directory) {
			return true
		}
		if !matcher.ShouldGoThrough(directory) {
			return false
		}
	}

	return matcher.IsPathMatched(relative)
}

// rsyncRule is one compiled filter rule of the import copy command.
type rsyncRule struct {
	include       bool
	directoryOnly bool
	expression    *regexp.Regexp
}

// compiledRsyncRules are the rules the import copy command passes to rsync, in the order
// rsync reads them, behind the exclusions the import daemon applies to every module path
// it serves.
func compiledRsyncRules(from string, scope ImportScope) ([]rsyncRule, error) {
	var passed []import_server.RsyncFilterRule
	for _, directory := range import_server.SystemExcludeDirs() {
		passed = append(passed, import_server.RsyncFilterRule{Pattern: directory})
	}
	passed = append(passed, import_server.RsyncFilterRules(from, scope.IncludePaths, scope.ExcludePaths)...)

	rules := make([]rsyncRule, 0, len(passed))
	for _, rule := range passed {
		compiled, err := compileRsyncRule(rule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, compiled)
	}

	return rules, nil
}

// A trailing slash matches directories only, a leading slash anchors the pattern to the
// root the import daemon serves the source image from, and any other pattern matches the
// end of a path at a directory boundary.
func compileRsyncRule(rule import_server.RsyncFilterRule) (rsyncRule, error) {
	compiled := rsyncRule{include: rule.Include}
	pattern := rule.Pattern
	if trimmed := strings.TrimSuffix(pattern, "/"); trimmed != pattern {
		compiled.directoryOnly, pattern = true, trimmed
	}

	start := `(?:^|/)`
	if strings.HasPrefix(pattern, "/") {
		start = `^`
	}
	body, err := rsyncPatternExpression(pattern)
	if err != nil {
		return rsyncRule{}, fmt.Errorf("no-data: the import copy passes rsync a filter %q this gate does not read: %w", rule.Pattern, err)
	}
	expression, err := regexp.Compile(start + body + `$`)
	if err != nil {
		return rsyncRule{}, fmt.Errorf("no-data: the import copy passes rsync a filter %q that cannot be read as a pattern: %w", rule.Pattern, err)
	}
	compiled.expression = expression

	return compiled, nil
}

// rsyncPatternExpression reads rsync's own wildcards: "*" stops at a directory boundary,
// "**" crosses it, "?" is one character that is not one, and brackets hold a character
// class. Everything else is literal, bytes and all. A pattern using a construct this does
// not read is refused rather than read as something else.
func rsyncPatternExpression(pattern string) (string, error) {
	var expression strings.Builder
	literal := 0
	for n := 0; n < len(pattern); n++ {
		width := 1
		switch pattern[n] {
		case '\\':
			return "", fmt.Errorf("an escape is not read here")
		case '*':
			if strings.HasPrefix(pattern[n:], "***") {
				return "", fmt.Errorf("a triple star is not read here")
			}
			expression.WriteString(regexp.QuoteMeta(pattern[literal:n]))
			if strings.HasPrefix(pattern[n:], "**") {
				width = 2
				expression.WriteString(`.*`)
			} else {
				expression.WriteString(`[^/]*`)
			}
		case '?':
			expression.WriteString(regexp.QuoteMeta(pattern[literal:n]))
			expression.WriteString(`[^/]`)
		case '[':
			class, classWidth, err := rsyncPatternClass(pattern[n:])
			if err != nil {
				return "", err
			}
			expression.WriteString(regexp.QuoteMeta(pattern[literal:n]))
			expression.WriteString(class)
			width = classWidth
		default:
			continue
		}
		n += width - 1
		literal = n + 1
	}
	expression.WriteString(regexp.QuoteMeta(pattern[literal:]))

	return expression.String(), nil
}

// An unterminated bracket is a literal one, as it is to rsync.
func rsyncPatternClass(pattern string) (string, int, error) {
	end := strings.IndexByte(pattern[1:], ']')
	if end < 0 {
		return regexp.QuoteMeta("["), 1, nil
	}
	body := pattern[1 : end+1]
	if strings.Contains(body, "[:") || strings.Contains(body, `\`) {
		return "", 0, fmt.Errorf("a character class %q is not read here", body)
	}
	if negated := strings.TrimPrefix(body, "!"); negated != body {
		body = "^" + negated
	}

	return "[" + body + "]", end + 2, nil
}

// rsync decides every path of the source on its own: the first rule matching it decides,
// an excluded directory is never descended into, and a directory that is included does
// not carry the descendants a later rule excludes.
func copiedByRsyncRules(rules []rsyncRule, from, relative string) bool {
	if relative == "." {
		return rsyncRulesCopy(rules, from, false)
	}

	parts := strings.Split(relative, "/")
	for n := 1; n < len(parts); n++ {
		if !rsyncRulesCopy(rules, path.Join(from, strings.Join(parts[:n], "/")), true) {
			return false
		}
	}

	return rsyncRulesCopy(rules, path.Join(from, relative), false)
}

func rsyncRulesCopy(rules []rsyncRule, name string, directory bool) bool {
	for _, rule := range rules {
		if rule.directoryOnly && !directory {
			continue
		}
		if rule.expression.MatchString(name) {
			return rule.include
		}
	}

	return true
}

func pathUnder(directory, name string) (string, bool) {
	if directory == "/" {
		return strings.TrimPrefix(name, "/"), name != "/"
	}
	if !strings.HasPrefix(name, directory+"/") {
		return "", false
	}

	return strings.TrimPrefix(name, directory+"/"), true
}

func rootedImportPath(name string) string {
	return "/" + strings.TrimPrefix(path.Clean("/"+name), "/")
}
