package main

import (
	"path/filepath"
	"testing"
)

func TestCurrentRepositoryReleasePolicy(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	findings, err := checkRepo(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 0 {
		for _, finding := range findings {
			t.Errorf("%s: %s", finding.path, finding.msg)
		}
	}
}
