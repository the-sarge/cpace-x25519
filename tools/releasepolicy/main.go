package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var shaRef = regexp.MustCompile(`^[0-9a-f]{40}$`)

type finding struct {
	path string
	msg  string
}

func main() {
	repoRoot := flag.String("repo-root", "../..", "repository root")
	flag.Parse()

	findings, err := checkRepo(*repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "release policy checker failed: %v\n", err)
		os.Exit(2)
	}
	if len(findings) > 0 {
		for _, f := range findings {
			fmt.Fprintf(os.Stderr, "%s: %s\n", f.path, f.msg)
		}
		os.Exit(1)
	}
	fmt.Println("release policy checker passed")
}

func checkRepo(repoRoot string) ([]finding, error) {
	workflowPath := filepath.Join(repoRoot, ".github", "workflows", "release.yml")
	workflow, err := loadYAML(workflowPath)
	if err != nil {
		return nil, err
	}
	var findings []finding
	findings = append(findings, checkWorkflow(workflowPath, workflow)...)
	findings = append(findings, checkAllowedSigners(repoRoot)...)
	findings = append(findings, checkRequiredScripts(repoRoot)...)
	return findings, nil
}

func loadYAML(path string) (*yaml.Node, error) {
	in, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(in, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(doc.Content) != 1 {
		return nil, fmt.Errorf("%s: expected one YAML document", path)
	}
	return doc.Content[0], nil
}

func checkWorkflow(path string, root *yaml.Node) []finding {
	c := checker{path: path}
	c.checkRoot(root)
	c.checkTriggers(root)
	c.checkTopPermissions(root)
	jobs := mapping(root, "jobs")
	if jobs == nil {
		c.fail("jobs", "missing jobs")
		return c.findings
	}
	c.checkJobSet(jobs)
	c.checkUnsupportedRefJob(jobs)
	c.checkVerifyTagJob(jobs)
	c.checkNeeds(jobs)
	c.checkActionPins(jobs)
	c.checkNoRunExpressions(jobs)
	c.checkSBOMJob(jobs)
	c.checkSBOMAttestationJob(jobs)
	c.checkReleaseJob(jobs)
	return c.findings
}

type checker struct {
	path     string
	findings []finding
}

func (c *checker) fail(nodePath, msg string) {
	c.findings = append(c.findings, finding{path: c.path + ":" + nodePath, msg: msg})
}

func (c *checker) checkRoot(root *yaml.Node) {
	if root.Kind != yaml.MappingNode {
		c.fail("$", "workflow must be a mapping")
	}
	if scalar(mapping(root, "name")) != "Release Validation" {
		c.fail("name", "workflow name must be Release Validation")
	}
}

func (c *checker) checkTriggers(root *yaml.Node) {
	on := mapping(root, "on")
	if on == nil {
		c.fail("on", "missing trigger block")
		return
	}
	push := mapping(on, "push")
	if push == nil {
		c.fail("on.push", "missing push trigger")
	} else if !contains(seqStrings(mapping(push, "tags")), "v*") {
		c.fail("on.push.tags", "push trigger must include v* tags")
	}
	if mapping(on, "workflow_dispatch") == nil {
		c.fail("on.workflow_dispatch", "missing workflow_dispatch trigger")
	}
}

func (c *checker) checkTopPermissions(root *yaml.Node) {
	permissions := mapping(root, "permissions")
	if permissions == nil {
		c.fail("permissions", "missing top-level permissions")
		return
	}
	if scalar(mapping(permissions, "contents")) != "read" {
		c.fail("permissions.contents", "top-level contents permission must be read")
	}
	for _, key := range mapKeys(permissions) {
		if key != "contents" {
			c.fail("permissions."+key, "unexpected top-level permission")
		}
	}
}

func (c *checker) checkJobSet(jobs *yaml.Node) {
	want := []string{"unsupported-ref", "verify-tag", "check", "race", "vuln", "gosec", "sbom", "sbom-attestation", "release"}
	for _, name := range want {
		if mapping(jobs, name) == nil {
			c.fail("jobs."+name, "missing required job")
		}
	}
}

func (c *checker) checkUnsupportedRefJob(jobs *yaml.Node) {
	job := mapping(jobs, "unsupported-ref")
	if job == nil {
		return
	}
	ifCond := scalar(mapping(job, "if"))
	if !strings.Contains(ifCond, "workflow_dispatch") || !strings.Contains(ifCond, "github.ref_type == 'tag'") || !strings.Contains(ifCond, "refs/tags/v") {
		c.fail("jobs.unsupported-ref.if", "unsupported-ref job must be limited to non-v* workflow_dispatch refs")
	}
	steps := steps(job)
	if len(steps) != 1 {
		c.fail("jobs.unsupported-ref.steps", "unsupported-ref job should have one explanatory failing step")
		return
	}
	run := scalar(mapping(steps[0], "run"))
	if !strings.Contains(run, "Release Validation workflow_dispatch runs must target a signed v* tag ref.") || !strings.Contains(run, "exit 1") {
		c.fail("jobs.unsupported-ref.steps[0].run", "unsupported-ref step must fail closed with the documented explanation")
	}
}

func (c *checker) checkVerifyTagJob(jobs *yaml.Node) {
	job := mapping(jobs, "verify-tag")
	if job == nil {
		return
	}
	if needs(job) != nil {
		c.fail("jobs.verify-tag.needs", "verify-tag must not depend on another job")
	}
	if !isTagGuard(scalar(mapping(job, "if"))) {
		c.fail("jobs.verify-tag.if", "verify-tag must run only for signed v* tag refs")
	}
	outputs := mapping(job, "outputs")
	for _, name := range []string{"release-tag", "sbom-file", "prerelease", "latest"} {
		if scalar(mapping(outputs, name)) == "" {
			c.fail("jobs.verify-tag.outputs."+name, "missing verify-tag output")
		}
	}
	verifyStep := stepByName(job, "Verify tag object and signature")
	if verifyStep == nil {
		c.fail("jobs.verify-tag.steps", "missing tag verification step")
		return
	}
	run := scalar(mapping(verifyStep, "run"))
	for _, fragment := range []string{
		`git fetch --force origin "refs/tags/$GITHUB_REF_NAME:refs/tags/$GITHUB_REF_NAME"`,
		`git cat-file -t "$GITHUB_REF_NAME"`,
		`test "$tag_type" = tag`,
		`git config gpg.ssh.allowedSignersFile .github/allowed_signers`,
		`git verify-tag "$GITHUB_REF_NAME"`,
	} {
		if !strings.Contains(run, fragment) {
			c.fail("jobs.verify-tag.steps.Verify tag object and signature.run", "missing required fragment: "+fragment)
		}
	}
	metaStep := stepByName(job, "Validate release tag metadata")
	if metaStep == nil {
		c.fail("jobs.verify-tag.steps", "missing release tag metadata step")
	} else if !strings.Contains(scalar(mapping(metaStep, "run")), `scripts/release-tag-metadata.sh "$GITHUB_REF_NAME" >> "$GITHUB_OUTPUT"`) {
		c.fail("jobs.verify-tag.steps.Validate release tag metadata.run", "metadata step must use scripts/release-tag-metadata.sh")
	}
}

func (c *checker) checkNeeds(jobs *yaml.Node) {
	want := map[string][]string{
		"check":            {"verify-tag"},
		"race":             {"verify-tag"},
		"vuln":             {"verify-tag"},
		"gosec":            {"verify-tag"},
		"sbom":             {"verify-tag", "check", "race", "vuln", "gosec"},
		"sbom-attestation": {"sbom"},
		"release":          {"verify-tag", "sbom", "sbom-attestation"},
	}
	for jobName, expected := range want {
		job := mapping(jobs, jobName)
		if job == nil {
			continue
		}
		got := needs(job)
		for _, need := range expected {
			if !contains(got, need) {
				c.fail("jobs."+jobName+".needs", "missing required need: "+need)
			}
		}
		if jobName != "release" && !isTagGuard(scalar(mapping(job, "if"))) {
			c.fail("jobs."+jobName+".if", "job must run only for signed v* tag refs")
		}
		if jobName == "release" && !isTagGuard(scalar(mapping(job, "if"))) {
			c.fail("jobs.release.if", "release job must be scoped to signed v* tag refs")
		}
	}
}

func (c *checker) checkActionPins(jobs *yaml.Node) {
	for _, ref := range actionUses(jobs) {
		action, version, ok := strings.Cut(ref.uses, "@")
		if !ok || action == "" || !shaRef.MatchString(version) {
			c.fail(ref.path+".uses", "action must be pinned by 40-character SHA")
		}
	}
}

func (c *checker) checkNoRunExpressions(jobs *yaml.Node) {
	for _, ref := range runSteps(jobs) {
		if strings.Contains(ref.run, "${{") {
			c.fail(ref.path+".run", "run steps must not interpolate GitHub expression contexts; pass values through env")
		}
	}
}

func (c *checker) checkSBOMJob(jobs *yaml.Node) {
	job := mapping(jobs, "sbom")
	if job == nil {
		return
	}
	outputs := mapping(job, "outputs")
	for _, name := range []string{"sbom-file", "sbom-sha256"} {
		if scalar(mapping(outputs, name)) == "" {
			c.fail("jobs.sbom.outputs."+name, "missing SBOM output")
		}
	}
	gen := stepByName(job, "Generate CycloneDX SBOM")
	if gen == nil {
		c.fail("jobs.sbom.steps", "missing SBOM generation step")
		return
	}
	if !strings.HasPrefix(scalar(mapping(gen, "uses")), "anchore/sbom-action@") {
		c.fail("jobs.sbom.steps.Generate CycloneDX SBOM.uses", "SBOM generation must use anchore/sbom-action")
	}
	with := mapping(gen, "with")
	expectScalars(c, "jobs.sbom.steps.Generate CycloneDX SBOM.with", with, map[string]string{
		"format":                "cyclonedx-json@1.5",
		"output-file":           "${{ needs.verify-tag.outputs.sbom-file }}",
		"syft-version":          "v1.45.1",
		"upload-artifact":       "false",
		"upload-release-assets": "false",
	})
	validate := stepByName(job, "Validate SBOM and compute checksum")
	if validate == nil {
		c.fail("jobs.sbom.steps", "missing SBOM validation step")
	} else {
		run := scalar(mapping(validate, "run"))
		for _, fragment := range []string{`scripts/validate-cyclonedx-sbom.sh "$sbom_file"`, `sha256sum "$sbom_file"`} {
			if !strings.Contains(run, fragment) {
				c.fail("jobs.sbom.steps.Validate SBOM and compute checksum.run", "missing required fragment: "+fragment)
			}
		}
	}
}

func (c *checker) checkSBOMAttestationJob(jobs *yaml.Node) {
	job := mapping(jobs, "sbom-attestation")
	if job == nil {
		return
	}
	permissions := mapping(job, "permissions")
	expectScalars(c, "jobs.sbom-attestation.permissions", permissions, map[string]string{
		"contents":     "read",
		"id-token":     "write",
		"attestations": "write",
	})
	attest := stepByName(job, "Attest SBOM")
	if attest == nil {
		c.fail("jobs.sbom-attestation.steps", "missing SBOM attestation step")
		return
	}
	if !strings.HasPrefix(scalar(mapping(attest, "uses")), "actions/attest@") {
		c.fail("jobs.sbom-attestation.steps.Attest SBOM.uses", "SBOM attestation must use actions/attest")
	}
	with := mapping(attest, "with")
	expectScalars(c, "jobs.sbom-attestation.steps.Attest SBOM.with", with, map[string]string{
		"subject-path": "dist/${{ needs.sbom.outputs.sbom-file }}",
		"sbom-path":    "dist/${{ needs.sbom.outputs.sbom-file }}",
	})
	prepare := stepByName(job, "Prepare Sigstore bundle asset")
	if prepare == nil {
		c.fail("jobs.sbom-attestation.steps", "missing Sigstore bundle preparation step")
	} else {
		run := scalar(mapping(prepare, "run"))
		if !strings.Contains(run, `bundle_dst="dist/${SBOM_FILE}.sigstore.json"`) || !strings.Contains(run, `cp "$ATTESTATION_BUNDLE_PATH" "$bundle_dst"`) {
			c.fail("jobs.sbom-attestation.steps.Prepare Sigstore bundle asset.run", "bundle preparation must copy the attest output to the release asset name")
		}
	}
}

func (c *checker) checkReleaseJob(jobs *yaml.Node) {
	job := mapping(jobs, "release")
	if job == nil {
		return
	}
	permissions := mapping(job, "permissions")
	expectScalars(c, "jobs.release.permissions", permissions, map[string]string{"contents": "write"})
	prepare := stepByName(job, "Prepare release notes and assets")
	if prepare == nil {
		c.fail("jobs.release.steps", "missing release preparation step")
	} else {
		run := scalar(mapping(prepare, "run"))
		for _, fragment := range []string{
			`scripts/validate-cyclonedx-sbom.sh "$sbom_path"`,
			`scripts/extract-release-notes.sh CHANGELOG.md "$RELEASE_TAG" > release-notes.md`,
			`SBOM SHA-256 (corruption detection only)`,
			`SBOM attestation bundle`,
		} {
			if !strings.Contains(run, fragment) {
				c.fail("jobs.release.steps.Prepare release notes and assets.run", "missing required fragment: "+fragment)
			}
		}
	}
	publish := stepByName(job, "Publish GitHub Release")
	if publish == nil {
		c.fail("jobs.release.steps", "missing publishing step")
		return
	}
	if scalar(mapping(publish, "if")) != "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')" {
		c.fail("jobs.release.steps.Publish GitHub Release.if", "publishing must be limited to v* tag pushes")
	}
	run := scalar(mapping(publish, "run"))
	for _, fragment := range []string{
		`gh release view "$tag"`,
		`refusing automated in-place asset replacement`,
		`gh release create "$tag" "$sbom_path" "$bundle_path"`,
		`--verify-tag`,
	} {
		if !strings.Contains(run, fragment) {
			c.fail("jobs.release.steps.Publish GitHub Release.run", "missing required fragment: "+fragment)
		}
	}
	env := mapping(publish, "env")
	if scalar(mapping(env, "GH_TOKEN")) != "${{ github.token }}" {
		c.fail("jobs.release.steps.Publish GitHub Release.env.GH_TOKEN", "publishing must use github.token")
	}
}

func checkAllowedSigners(repoRoot string) []finding {
	path := filepath.Join(repoRoot, ".github", "allowed_signers")
	in, err := os.ReadFile(path)
	if err != nil {
		return []finding{{path: path, msg: err.Error()}}
	}
	if !strings.Contains(string(in), "the-sarge@the-sarge.com ") {
		return []finding{{path: path, msg: "missing documented maintainer principal"}}
	}
	return nil
}

func checkRequiredScripts(repoRoot string) []finding {
	var findings []finding
	for _, path := range []string{
		"scripts/release-tag-metadata.sh",
		"scripts/validate-cyclonedx-sbom.sh",
		"scripts/extract-release-notes.sh",
	} {
		full := filepath.Join(repoRoot, path)
		info, err := os.Stat(full)
		switch {
		case errors.Is(err, os.ErrNotExist):
			findings = append(findings, finding{path: full, msg: "missing required release helper"})
		case err != nil:
			findings = append(findings, finding{path: full, msg: err.Error()})
		case info.IsDir():
			findings = append(findings, finding{path: full, msg: "expected file, got directory"})
		}
	}
	return findings
}

func expectScalars(c *checker, nodePath string, n *yaml.Node, want map[string]string) {
	if n == nil {
		c.fail(nodePath, "missing mapping")
		return
	}
	for key, expected := range want {
		if got := scalar(mapping(n, key)); got != expected {
			c.fail(nodePath+"."+key, fmt.Sprintf("got %q, want %q", got, expected))
		}
	}
}

type actionRef struct {
	path string
	uses string
}

func actionUses(jobs *yaml.Node) []actionRef {
	var out []actionRef
	for _, jobName := range mapKeys(jobs) {
		job := mapping(jobs, jobName)
		for idx, step := range steps(job) {
			if uses := scalar(mapping(step, "uses")); uses != "" {
				out = append(out, actionRef{path: fmt.Sprintf("jobs.%s.steps[%d]", jobName, idx), uses: uses})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

type runRef struct {
	path string
	run  string
}

func runSteps(jobs *yaml.Node) []runRef {
	var out []runRef
	for _, jobName := range mapKeys(jobs) {
		job := mapping(jobs, jobName)
		for idx, step := range steps(job) {
			if run := scalar(mapping(step, "run")); run != "" {
				out = append(out, runRef{path: fmt.Sprintf("jobs.%s.steps[%d]", jobName, idx), run: run})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

func stepByName(job *yaml.Node, name string) *yaml.Node {
	for _, step := range steps(job) {
		if scalar(mapping(step, "name")) == name {
			return step
		}
	}
	return nil
}

func steps(job *yaml.Node) []*yaml.Node {
	n := mapping(job, "steps")
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

func needs(job *yaml.Node) []string {
	n := mapping(job, "needs")
	switch {
	case n == nil:
		return nil
	case n.Kind == yaml.ScalarNode:
		return []string{n.Value}
	case n.Kind == yaml.SequenceNode:
		return seqStrings(n)
	default:
		return nil
	}
}

func isTagGuard(in string) bool {
	return strings.Contains(in, "github.ref_type == 'tag'") && strings.Contains(in, "startsWith(github.ref, 'refs/tags/v')")
}

func mapping(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func seqStrings(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]string, 0, len(n.Content))
	for _, item := range n.Content {
		out = append(out, scalar(item))
	}
	return out
}

func mapKeys(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]string, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		out = append(out, n.Content[i].Value)
	}
	sort.Strings(out)
	return out
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
