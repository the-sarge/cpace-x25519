package cpace

import (
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode"
)

type fuzzTargetSelfContainmentViolation struct {
	TargetFile      string
	AffectedTargets []string
	Name            string
	DeclFile        string
	Detail          string
}

func TestFuzzTargetRegistrySelfContainedFiles(t *testing.T) {
	entries := readFuzzTargetRegistry(t)
	fset, files := parseRootPackageGoFiles(t)

	// Keep this under plain go test: each registered fuzz target file must stay
	// self-contained for OSS-Fuzz native Go rewriting.
	// OSS-Fuzz rewrites each registered target file independently: production
	// declarations and same-file test helpers are available, but helpers from
	// other *_test.go files are not.
	violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries)
	if len(violations) == 0 {
		return
	}

	var lines []string
	for _, violation := range violations {
		if violation.Detail != "" {
			lines = append(lines, fmt.Sprintf("registered target file %s (targets: %s) is not self-contained: %s", violation.TargetFile, strings.Join(violation.AffectedTargets, ","), violation.Detail))
			continue
		}
		lines = append(lines, fmt.Sprintf("registered target file %s (targets: %s) depends on %s from %s", violation.TargetFile, strings.Join(violation.AffectedTargets, ","), violation.Name, violation.DeclFile))
	}
	t.Fatalf("registered fuzz target files must be self-contained for OSS-Fuzz native Go rewriting:\n%s", strings.Join(lines, "\n"))
}

func TestFuzzTargetSelfContainmentRejectsCrossFileTestHelpers(t *testing.T) {
	fset := token.NewFileSet()
	files := []*ast.File{
		parseGoSource(t, fset, "target_test.go", `package p

import "testing"

func FuzzTarget(f *testing.F) {
	helper()
}
`),
		parseGoSource(t, fset, "helper_test.go", `package p

func helper() {}
`),
	}
	entries := []fuzzTargetRegistryEntry{{
		Target:  "FuzzTarget",
		Package: ".",
		Binary:  "fuzz_target",
	}}

	violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries)
	if len(violations) != 1 {
		t.Fatalf("violations count=%d want 1: %#v", len(violations), violations)
	}
	if got := violations[0]; !reflect.DeepEqual(got.AffectedTargets, []string{"FuzzTarget"}) || got.TargetFile != "target_test.go" || got.Name != "helper" || got.DeclFile != "helper_test.go" {
		t.Fatalf("violation=%#v", got)
	}
}

func TestFuzzTargetSelfContainmentRejectsCrossFileTestMethods(t *testing.T) {
	fset := token.NewFileSet()
	files := []*ast.File{
		parseGoSource(t, fset, "prod.go", `package p

type productionReceiver struct{}
`),
		parseGoSource(t, fset, "target_test.go", `package p

import "testing"

func FuzzTarget(f *testing.F) {
	var x productionReceiver
	x.helper()
}
`),
		parseGoSource(t, fset, "helper_test.go", `package p

func (productionReceiver) helper() {}
`),
	}
	entries := []fuzzTargetRegistryEntry{{
		Target:  "FuzzTarget",
		Package: ".",
		Binary:  "fuzz_target",
	}}

	violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries)
	if len(violations) != 1 {
		t.Fatalf("violations count=%d want 1: %#v", len(violations), violations)
	}
	if got := violations[0]; !reflect.DeepEqual(got.AffectedTargets, []string{"FuzzTarget"}) || got.TargetFile != "target_test.go" || got.Name != "helper" || got.DeclFile != "helper_test.go" {
		t.Fatalf("violation=%#v", got)
	}
}

func TestFuzzTargetSelfContainmentRejectsCrossFileTestMethodsOnLocalReceivers(t *testing.T) {
	fset := token.NewFileSet()
	files := []*ast.File{
		parseGoSource(t, fset, "target_test.go", `package p

import "testing"

type localReceiver struct{}

func FuzzTarget(f *testing.F) {
	var x localReceiver
	x.crossFileHelper()
}
`),
		parseGoSource(t, fset, "helper_test.go", `package p

func (localReceiver) crossFileHelper() {}
`),
	}
	entries := []fuzzTargetRegistryEntry{{
		Target:  "FuzzTarget",
		Package: ".",
		Binary:  "fuzz_target",
	}}

	violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries)
	if len(violations) != 1 {
		t.Fatalf("violations count=%d want 1: %#v", len(violations), violations)
	}
	if got := violations[0]; !reflect.DeepEqual(got.AffectedTargets, []string{"FuzzTarget"}) || got.TargetFile != "target_test.go" || got.Name != "crossFileHelper" || got.DeclFile != "helper_test.go" {
		t.Fatalf("violation=%#v", got)
	}
}

func TestFuzzTargetSelfContainmentRejectsImplicitCrossFileTestMethods(t *testing.T) {
	fset := token.NewFileSet()
	files := []*ast.File{
		parseGoSource(t, fset, "prod.go", `package p

type Receiver struct{}
`),
		parseGoSource(t, fset, "target_test.go", `package p

import "testing"

type Sink interface {
	M()
}

func FuzzTarget(f *testing.F) {
	accept(Receiver{})
}

func accept(Sink) {}
`),
		parseGoSource(t, fset, "helper_test.go", `package p

func (Receiver) M() {}
`),
	}
	entries := []fuzzTargetRegistryEntry{{
		Target:  "FuzzTarget",
		Package: ".",
		Binary:  "fuzz_target",
	}}

	violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries)
	if len(violations) != 1 {
		t.Fatalf("violations count=%d want 1: %#v", len(violations), violations)
	}
	if got := violations[0]; !reflect.DeepEqual(got.AffectedTargets, []string{"FuzzTarget"}) || got.TargetFile != "target_test.go" || got.Detail == "" {
		t.Fatalf("violation=%#v", got)
	}
}

func TestFuzzTargetSelfContainmentAllowsModuleImportResolutionNoise(t *testing.T) {
	fset := token.NewFileSet()
	files := []*ast.File{
		parseGoSource(t, fset, "target_test.go", `package p

import (
	_ "filippo.io/edwards25519/field"
	"testing"
)

func FuzzTarget(f *testing.F) {}
`),
	}
	entries := []fuzzTargetRegistryEntry{{
		Target:  "FuzzTarget",
		Package: ".",
		Binary:  "fuzz_target",
	}}

	if violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries); len(violations) != 0 {
		t.Fatalf("violations count=%d want 0: %#v", len(violations), violations)
	}
}

func TestFuzzTargetSelfContainmentRecognizesAliasedTestingImport(t *testing.T) {
	fset := token.NewFileSet()
	files := []*ast.File{
		parseGoSource(t, fset, "target_test.go", `package p

import t "testing"

func FuzzTarget(f *t.F) {
	helper()
}
`),
		parseGoSource(t, fset, "helper_test.go", `package p

func helper() {}
`),
	}
	entries := []fuzzTargetRegistryEntry{{
		Target:  "FuzzTarget",
		Package: ".",
		Binary:  "fuzz_target",
	}}

	definedTargets := discoverDefinedFuzzTargetsInFiles(files)
	if _, ok := definedTargets["FuzzTarget"]; !ok {
		t.Fatalf("aliased testing import target was not discovered: %v", sortedKeys(definedTargets))
	}
	violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries)
	if len(violations) != 1 {
		t.Fatalf("violations count=%d want 1: %#v", len(violations), violations)
	}
	if got := violations[0]; !reflect.DeepEqual(got.AffectedTargets, []string{"FuzzTarget"}) || got.TargetFile != "target_test.go" || got.Name != "helper" || got.DeclFile != "helper_test.go" {
		t.Fatalf("violation=%#v", got)
	}
}

func TestFuzzTargetSelfContainmentRejectsCrossFileTestConst(t *testing.T) {
	fset := token.NewFileSet()
	files := []*ast.File{
		parseGoSource(t, fset, "target_test.go", `package p

import "testing"

func FuzzTarget(f *testing.F) {
	_ = crossFileConst
}
`),
		parseGoSource(t, fset, "helper_test.go", `package p

const crossFileConst = 1
`),
	}
	entries := []fuzzTargetRegistryEntry{{
		Target:  "FuzzTarget",
		Package: ".",
		Binary:  "fuzz_target",
	}}

	violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries)
	if len(violations) != 1 {
		t.Fatalf("violations count=%d want 1: %#v", len(violations), violations)
	}
	if got := violations[0]; !reflect.DeepEqual(got.AffectedTargets, []string{"FuzzTarget"}) || got.TargetFile != "target_test.go" || got.Name != "crossFileConst" || got.DeclFile != "helper_test.go" {
		t.Fatalf("violation=%#v", got)
	}
}

func TestFuzzTargetSelfContainmentAllowsSameFileTestHelpers(t *testing.T) {
	fset := token.NewFileSet()
	files := []*ast.File{
		parseGoSource(t, fset, "target_test.go", `package p

import "testing"

func FuzzTarget(f *testing.F) {
	helper()
}

func helper() {}
`),
	}
	entries := []fuzzTargetRegistryEntry{{
		Target:  "FuzzTarget",
		Package: ".",
		Binary:  "fuzz_target",
	}}

	if violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries); len(violations) != 0 {
		t.Fatalf("violations count=%d want 0: %#v", len(violations), violations)
	}
}

func TestFuzzTargetSelfContainmentAllowsProductionHelpers(t *testing.T) {
	fset := token.NewFileSet()
	files := []*ast.File{
		parseGoSource(t, fset, "prod.go", `package p

func helper() {}
`),
		parseGoSource(t, fset, "target_test.go", `package p

import "testing"

func FuzzTarget(f *testing.F) {
	helper()
}
`),
	}
	entries := []fuzzTargetRegistryEntry{{
		Target:  "FuzzTarget",
		Package: ".",
		Binary:  "fuzz_target",
	}}

	if violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries); len(violations) != 0 {
		t.Fatalf("violations count=%d want 0: %#v", len(violations), violations)
	}
}

func TestFuzzTargetSelfContainmentReportsAllTargetsInFile(t *testing.T) {
	fset := token.NewFileSet()
	files := []*ast.File{
		parseGoSource(t, fset, "target_test.go", `package p

import "testing"

func FuzzOne(f *testing.F) {
	helper()
}

func FuzzTwo(f *testing.F) {}
`),
		parseGoSource(t, fset, "helper_test.go", `package p

func helper() {}
`),
	}
	entries := []fuzzTargetRegistryEntry{
		{Target: "FuzzTwo", Package: ".", Binary: "fuzz_two"},
		{Target: "FuzzOne", Package: ".", Binary: "fuzz_one"},
	}

	violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries)
	if len(violations) != 1 {
		t.Fatalf("violations count=%d want 1: %#v", len(violations), violations)
	}
	if got := violations[0]; !reflect.DeepEqual(got.AffectedTargets, []string{"FuzzOne", "FuzzTwo"}) || got.TargetFile != "target_test.go" || got.Name != "helper" || got.DeclFile != "helper_test.go" {
		t.Fatalf("violation=%#v", got)
	}
}

func TestFuzzTargetSelfContainmentNormalizesFilePaths(t *testing.T) {
	fset := token.NewFileSet()
	dir := t.TempDir()
	files := []*ast.File{
		parseGoSource(t, fset, filepath.Join(dir, "target_test.go"), `package p

import "testing"

func FuzzTarget(f *testing.F) {
	helper()
}
`),
		parseGoSource(t, fset, filepath.Join(dir, "helper_test.go"), `package p

func helper() {}
`),
	}
	entries := []fuzzTargetRegistryEntry{{
		Target:  "FuzzTarget",
		Package: ".",
		Binary:  "fuzz_target",
	}}

	violations := findFuzzTargetSelfContainmentViolations(t, fset, files, entries)
	if len(violations) != 1 {
		t.Fatalf("violations count=%d want 1: %#v", len(violations), violations)
	}
	if got := violations[0]; got.TargetFile != "target_test.go" || got.DeclFile != "helper_test.go" {
		t.Fatalf("violation=%#v", got)
	}
}

func findFuzzTargetSelfContainmentViolations(tb testing.TB, fset *token.FileSet, files []*ast.File, entries []fuzzTargetRegistryEntry) []fuzzTargetSelfContainmentViolation {
	tb.Helper()

	registeredTargets := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Package == "." {
			registeredTargets[entry.Target] = struct{}{}
		}
	}

	targetsByFile := make(map[string]map[string]struct{})
	for _, file := range files {
		filename := goFileName(fset, file.Pos())
		testingNames := testingImportNames(file)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if _, ok := registeredTargets[fn.Name.Name]; !ok || !hasTestingFSignature(fn, testingNames) {
				continue
			}
			if targetsByFile[filename] == nil {
				targetsByFile[filename] = make(map[string]struct{})
			}
			targetsByFile[filename][fn.Name.Name] = struct{}{}
		}
	}

	info := &types.Info{
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	// The standard importer does not resolve module-only dependencies here; go
	// test remains the compiler gate. This guard only needs same-package object
	// resolution to find dependencies on declarations from other *_test.go files.
	conf := types.Config{
		Importer: importer.Default(),
		Error:    func(error) {},
	}
	pkg, _ := conf.Check(packageName(files), fset, files, info)
	if pkg == nil {
		tb.Fatal("type-check fuzz target package did not return a package")
	}

	seen := make(map[string]struct{})
	var violations []fuzzTargetSelfContainmentViolation
	affectedTargets := func(targetFile string) []string {
		return sortedKeys(targetsByFile[targetFile])
	}
	addViolation := func(targetFile string, obj types.Object) {
		if obj == nil || !obj.Pos().IsValid() {
			return
		}
		if obj.Pkg() != pkg {
			return
		}
		declFile := goFileName(fset, obj.Pos())
		if declFile == "" || declFile == targetFile || !isTestGoFile(declFile) {
			return
		}
		targets := affectedTargets(targetFile)
		key := strings.Join(targets, ",") + "\x00" + targetFile + "\x00" + obj.Name() + "\x00" + declFile
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		violations = append(violations, fuzzTargetSelfContainmentViolation{
			TargetFile:      targetFile,
			AffectedTargets: targets,
			Name:            obj.Name(),
			DeclFile:        declFile,
		})
	}
	addTypeCheckViolation := func(targetFile, detail string) {
		for _, violation := range violations {
			if violation.TargetFile == targetFile && violation.Name != "" && detailMentionsObjectName(detail, violation.Name) {
				return
			}
		}
		targets := affectedTargets(targetFile)
		key := strings.Join(targets, ",") + "\x00" + targetFile + "\x00" + detail
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		violations = append(violations, fuzzTargetSelfContainmentViolation{
			TargetFile:      targetFile,
			AffectedTargets: targets,
			Detail:          detail,
		})
	}

	for ident, obj := range info.Uses {
		useFile := goFileName(fset, ident.Pos())
		if _, ok := targetsByFile[useFile]; !ok {
			continue
		}
		addViolation(useFile, obj)
	}
	for selector, selection := range info.Selections {
		useFile := goFileName(fset, selector.Sel.Pos())
		if _, ok := targetsByFile[useFile]; !ok {
			continue
		}
		addViolation(useFile, selection.Obj())
	}
	for targetFile := range targetsByFile {
		for _, err := range selfContainedTargetTypeErrors(fset, files, targetFile) {
			addTypeCheckViolation(targetFile, err)
		}
	}

	sort.Slice(violations, func(i, j int) bool {
		a, b := violations[i], violations[j]
		if a.TargetFile != b.TargetFile {
			return a.TargetFile < b.TargetFile
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.DeclFile != b.DeclFile {
			return a.DeclFile < b.DeclFile
		}
		return strings.Join(a.AffectedTargets, ",") < strings.Join(b.AffectedTargets, ",")
	})
	return violations
}

func selfContainedTargetTypeErrors(fset *token.FileSet, files []*ast.File, targetFile string) []string {
	var isolated []*ast.File
	for _, file := range files {
		filename := goFileName(fset, file.Pos())
		if filename == targetFile || !isTestGoFile(filename) {
			isolated = append(isolated, file)
		}
	}

	var details []string
	conf := types.Config{
		Importer: importer.Default(),
		Error: func(err error) {
			var typeErr types.Error
			if !errors.As(err, &typeErr) {
				return
			}
			if goFileName(fset, typeErr.Pos) == targetFile {
				if isImportResolutionNoise(fset, files, targetFile, typeErr) {
					return
				}
				details = append(details, typeErr.Msg)
			}
		},
	}
	_, _ = conf.Check(packageName(isolated), fset, isolated, nil)
	sort.Strings(details)
	return details
}

func isImportResolutionNoise(fset *token.FileSet, files []*ast.File, targetFile string, typeErr types.Error) bool {
	if strings.HasPrefix(typeErr.Msg, "could not import") || strings.Contains(typeErr.Msg, "cannot find package") {
		return true
	}
	for _, file := range files {
		if goFileName(fset, file.Pos()) != targetFile {
			continue
		}
		for _, spec := range file.Imports {
			if spec.Pos() <= typeErr.Pos && typeErr.Pos <= spec.End() {
				return true
			}
		}
	}
	return false
}

func TestDetailMentionsObjectNameUsesIdentifierBoundaries(t *testing.T) {
	tests := []struct {
		detail string
		name   string
		want   bool
	}{
		{detail: "undefined: helper", name: "helper", want: true},
		{detail: `undefined: "helper"`, name: "helper", want: true},
		{detail: "cannot use helper() as Sink", name: "helper", want: true},
		{detail: "undefined: helperExtra", name: "helper", want: false},
		{detail: "undefined: helper_extra", name: "helper", want: false},
	}

	for _, tt := range tests {
		if got := detailMentionsObjectName(tt.detail, tt.name); got != tt.want {
			t.Fatalf("detailMentionsObjectName(%q, %q) = %v, want %v", tt.detail, tt.name, got, tt.want)
		}
	}
}

func detailMentionsObjectName(detail, name string) bool {
	for _, token := range strings.FieldsFunc(detail, func(r rune) bool {
		return r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if token == name {
			return true
		}
	}
	return false
}
