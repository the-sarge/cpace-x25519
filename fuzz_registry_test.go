package cpace

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
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

func TestFuzzTargetRegistryDiscoveryUsesPackageDirectory(t *testing.T) {
	modulePath := packageFilePath(t, "go.mod")
	if !filepath.IsAbs(modulePath) {
		t.Fatalf("packageFilePath returned %q, want absolute path", modulePath)
	}
	if _, err := os.Stat(modulePath); err != nil {
		t.Fatalf("stat package file %s: %v", modulePath, err)
	}
	if files := packageSourceFiles(t, "*_test.go"); len(files) == 0 || !filepath.IsAbs(files[0]) {
		t.Fatalf("packageSourceFiles returned %v, want absolute test files", files)
	}

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

func TestFuzzTargetRegistryDiscoveryIgnoresExternalPackageTargets(t *testing.T) {
	fset := token.NewFileSet()
	files := []*ast.File{
		parseGoSource(t, fset, "internal_test.go", `package cpace

import "testing"

func FuzzInternal(f *testing.F) {}
`),
		parseGoSource(t, fset, "external_test.go", `package cpace_test

import "testing"

func FuzzExternal(f *testing.F) {}
`),
	}

	targets := discoverDefinedFuzzTargetsInFiles(filesInPackage(files, "cpace"))
	if _, ok := targets["FuzzInternal"]; !ok {
		t.Fatalf("internal package fuzz target was not discovered: %v", sortedKeys(targets))
	}
	if _, ok := targets["FuzzExternal"]; ok {
		t.Fatalf("external package fuzz target was discovered: %v", sortedKeys(targets))
	}
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
	if ok {
		sourceDir := filepath.Dir(sourceFile)
		if filepath.IsAbs(sourceDir) {
			if _, err := os.Stat(filepath.Join(sourceDir, "go.mod")); err == nil {
				return filepath.Join(sourceDir, name)
			}
		}
	}

	wd, err := os.Getwd()
	if err != nil {
		tb.Fatalf("locate package working directory: %v", err)
	}
	root, err := moduleRootFrom(wd)
	if err != nil {
		tb.Fatalf("locate package module root: %v", err)
	}
	return filepath.Join(root, name)
}

func moduleRootFrom(dir string) (string, error) {
	start := dir
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", start)
		}
		dir = parent
	}
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

	return discoverDefinedFuzzTargetsInFiles(filesInPackage(parsedFiles, "cpace"))
}

func filesInPackage(files []*ast.File, name string) []*ast.File {
	filtered := make([]*ast.File, 0, len(files))
	for _, file := range files {
		if file.Name.Name == name {
			filtered = append(filtered, file)
		}
	}
	return filtered
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
