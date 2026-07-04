package cpace

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

type fuzzTargetRegistryEntry struct {
	Target  string `json:"target"`
	Package string `json:"package"`
	Binary  string `json:"binary"`
}

type ossFuzzBuildTarget struct {
	Module string
	Target string
	Binary string
	Line   string
}

type fuzzTargetSelfContainmentViolation struct {
	TargetFile      string
	AffectedTargets []string
	Name            string
	DeclFile        string
	Detail          string
}

var fuzzTargetBinaryPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

func TestFuzzTargetRegistrySchema(t *testing.T) {
	entries := readFuzzTargetRegistry(t)
	seenTargets := make(map[string]struct{}, len(entries))
	seenBinaries := make(map[string]struct{}, len(entries))

	for i, entry := range entries {
		if entry.Target == "" {
			t.Errorf("entry %d has empty target", i)
		}
		if entry.Package != "." {
			t.Errorf("entry %d target %q package = %q, want .", i, entry.Target, entry.Package)
		}
		if entry.Binary == "" {
			t.Errorf("entry %d target %q has empty binary", i, entry.Target)
		} else if !fuzzTargetBinaryPattern.MatchString(entry.Binary) {
			t.Errorf("entry %d target %q binary = %q, want match %s", i, entry.Target, entry.Binary, fuzzTargetBinaryPattern)
		}

		if _, ok := seenTargets[entry.Target]; ok {
			t.Errorf("duplicate target %q", entry.Target)
		}
		seenTargets[entry.Target] = struct{}{}

		if _, ok := seenBinaries[entry.Binary]; ok {
			t.Errorf("duplicate binary %q", entry.Binary)
		}
		seenBinaries[entry.Binary] = struct{}{}
	}
}

func TestFuzzTargetRegistryMatchesDefinedTargets(t *testing.T) {
	entries := readFuzzTargetRegistry(t)
	registeredTargets := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		registeredTargets[entry.Target] = struct{}{}
	}

	definedTargets := discoverDefinedFuzzTargets(t)
	if len(definedTargets) == 0 {
		t.Fatal("no func FuzzXxx(f *testing.F) definitions found")
	}

	if !reflect.DeepEqual(sortedKeys(registeredTargets), sortedKeys(definedTargets)) {
		t.Fatalf("registered fuzz targets do not match defined fuzz targets\nregistered: %v\ndefined:    %v", sortedKeys(registeredTargets), sortedKeys(definedTargets))
	}
}

func TestFuzzTargetRegistryMatchesOSSFuzzBuild(t *testing.T) {
	entries := readFuzzTargetRegistry(t)
	buildTargets := readOSSFuzzBuildTargets(t)
	if len(buildTargets) == 0 {
		t.Fatal("ossfuzz/build.sh has no compile_native_go_fuzzer lines")
	}

	module := readModulePath(t)
	for i, target := range buildTargets {
		if target.Module != module {
			t.Errorf("ossfuzz/build.sh compile line %d module = %q, want %q", i, target.Module, module)
		}
	}

	wantLines := make([]string, 0, len(entries))
	for _, entry := range entries {
		wantLines = append(wantLines, fmt.Sprintf("compile_native_go_fuzzer %s %s %s", module, entry.Target, entry.Binary))
	}

	gotLines := make([]string, 0, len(buildTargets))
	for _, target := range buildTargets {
		gotLines = append(gotLines, target.Line)
	}

	if !reflect.DeepEqual(gotLines, wantLines) {
		t.Fatalf("ossfuzz/build.sh compile lines do not match .github/fuzz-targets.json\nwant:\n%s\ngot:\n%s", strings.Join(wantLines, "\n"), strings.Join(gotLines, "\n"))
	}
}

func TestFuzzTargetRegistrySelfContainedFiles(t *testing.T) {
	entries := readFuzzTargetRegistry(t)
	fset, files := parseRootPackageGoFiles(t)

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

func TestFuzzTargetRegistryDiscoveryUsesPackageDirectory(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir away from package: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	fset, files := parseRootPackageGoFiles(t)
	if len(files) == 0 {
		t.Fatal("parseRootPackageGoFiles returned no files")
	}
	if got := goFileName(fset, files[0].Pos()); got == "" || filepath.IsAbs(got) {
		t.Fatalf("normalized file name = %q, want package-relative basename", got)
	}
	if targets := discoverDefinedFuzzTargets(t); len(targets) == 0 {
		t.Fatal("discoverDefinedFuzzTargets returned no targets")
	}
	if entries := readFuzzTargetRegistry(t); len(entries) == 0 {
		t.Fatal("readFuzzTargetRegistry returned no entries")
	}
	if targets := readOSSFuzzBuildTargets(t); len(targets) == 0 {
		t.Fatal("readOSSFuzzBuildTargets returned no targets")
	}
	if module := readModulePath(t); module == "" {
		t.Fatal("readModulePath returned empty module")
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

func parseRootPackageGoFiles(tb testing.TB) (*token.FileSet, []*ast.File) {
	tb.Helper()

	names := packageSourceFiles(tb, "*.go")

	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range names {
		parsed, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			tb.Fatalf("parse %s: %v", name, err)
		}
		if parsed.Name.Name != "cpace" {
			continue
		}
		files = append(files, parsed)
	}
	if len(files) == 0 {
		tb.Fatal("no root package Go files found")
	}
	return fset, files
}

func packageSourceFiles(tb testing.TB, pattern string) []string {
	tb.Helper()

	names, err := filepath.Glob(packageFilePath(tb, pattern))
	if err != nil {
		tb.Fatalf("list %s files: %v", pattern, err)
	}
	sort.Strings(names)
	return names
}

func packageFilePath(tb testing.TB, name string) string {
	tb.Helper()

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("locate fuzz registry test source")
	}
	return filepath.Join(filepath.Dir(sourceFile), name)
}

func goFileName(fset *token.FileSet, pos token.Pos) string {
	filename := fset.Position(pos).Filename
	if filename == "" {
		return ""
	}
	return filepath.Base(filepath.Clean(filename))
}

func isTestGoFile(filename string) bool {
	return strings.HasSuffix(goFileBase(filename), "_test.go")
}

func goFileBase(filename string) string {
	if filename == "" {
		return ""
	}
	return filepath.Base(filepath.Clean(filename))
}

func packageName(files []*ast.File) string {
	if len(files) == 0 {
		return "cpace"
	}
	return files[0].Name.Name
}

func parseGoSource(tb testing.TB, fset *token.FileSet, name, source string) *ast.File {
	tb.Helper()
	parsed, err := parser.ParseFile(fset, name, source, 0)
	if err != nil {
		tb.Fatalf("parse %s: %v", name, err)
	}
	return parsed
}

func readFuzzTargetRegistry(tb testing.TB) []fuzzTargetRegistryEntry {
	tb.Helper()

	data, err := os.ReadFile(packageFilePath(tb, ".github/fuzz-targets.json"))
	if err != nil {
		tb.Fatalf("read .github/fuzz-targets.json: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var entries []fuzzTargetRegistryEntry
	if err := decoder.Decode(&entries); err != nil {
		tb.Fatalf("parse .github/fuzz-targets.json: %v", err)
	}
	if len(entries) == 0 {
		tb.Fatal(".github/fuzz-targets.json contains no targets")
	}

	return entries
}

func discoverDefinedFuzzTargets(tb testing.TB) map[string]struct{} {
	tb.Helper()

	files := packageSourceFiles(tb, "*_test.go")

	fset := token.NewFileSet()
	var parsedFiles []*ast.File
	for _, name := range files {
		parsed, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			tb.Fatalf("parse %s: %v", name, err)
		}
		parsedFiles = append(parsedFiles, parsed)
	}

	return discoverDefinedFuzzTargetsInFiles(parsedFiles)
}

func discoverDefinedFuzzTargetsInFiles(files []*ast.File) map[string]struct{} {
	targets := make(map[string]struct{})
	for _, file := range files {
		testingNames := testingImportNames(file)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
				continue
			}
			if hasTestingFSignature(fn, testingNames) {
				targets[fn.Name.Name] = struct{}{}
			}
		}
	}
	return targets
}

func hasTestingFSignature(fn *ast.FuncDecl, testingNames map[string]struct{}) bool {
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return false
	}
	if fn.Type.Results != nil && len(fn.Type.Results.List) != 0 {
		return false
	}
	param := fn.Type.Params.List[0]
	if len(param.Names) != 1 {
		return false
	}
	star, ok := param.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok || selector.Sel.Name != "F" {
		return false
	}
	_, ok = testingNames[pkg.Name]
	return ok
}

func testingImportNames(file *ast.File) map[string]struct{} {
	names := make(map[string]struct{})
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != "testing" {
			continue
		}
		name := "testing"
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "_" || name == "." {
			continue
		}
		names[name] = struct{}{}
	}
	return names
}

func readOSSFuzzBuildTargets(tb testing.TB) []ossFuzzBuildTarget {
	tb.Helper()

	data, err := os.ReadFile(packageFilePath(tb, "ossfuzz/build.sh"))
	if err != nil {
		tb.Fatalf("read ossfuzz/build.sh: %v", err)
	}

	var targets []ossFuzzBuildTarget
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "compile_native_go_fuzzer ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			tb.Fatalf("ossfuzz/build.sh compile line %q has %d fields, want 4", line, len(fields))
		}
		targets = append(targets, ossFuzzBuildTarget{
			Module: fields[1],
			Target: fields[2],
			Binary: fields[3],
			Line:   line,
		})
	}
	if err := scanner.Err(); err != nil {
		tb.Fatalf("scan ossfuzz/build.sh: %v", err)
	}

	return targets
}

func readModulePath(tb testing.TB) string {
	tb.Helper()

	data, err := os.ReadFile(packageFilePath(tb, "go.mod"))
	if err != nil {
		tb.Fatalf("read go.mod: %v", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "module" {
			return fields[1]
		}
	}
	if err := scanner.Err(); err != nil {
		tb.Fatalf("scan go.mod: %v", err)
	}
	tb.Fatal("go.mod has no module line")
	return ""
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
