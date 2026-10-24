package tests

// Generador del workflow de GitHub Actions para CI del L1.

import (
	"os"
	"path/filepath"
)

// CIWorkflowYAML es el workflow CI (build, vet, test, race smoke).
const CIWorkflowYAML = `name: l1-ci
on:
  push:
    branches: [main, master]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - name: Build
        run: go build ./...
      - name: Vet
        run: go vet ./...
      - name: Test short
        run: go test ./... -short -count=1 -timeout 120s
      - name: Test race (sanity subset)
        run: go test ./tests/ -run 'TestTypes|TestCrypto|TestMerkle|TestTrie' -race -count=1 -timeout 120s
`

// WriteCIWorkflow escribe .github/workflows/l1-ci.yml bajo root.
func WriteCIWorkflow(root string) error {
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "l1-ci.yml"), []byte(CIWorkflowYAML), 0o644)
}

// WriteAllTestnetAssets genera génesis, compose, scripts, CI y docs en root.
func WriteAllTestnetAssets(root string) error {
	cfg := filepath.Join(root, "config")
	if err := WriteTestnetGenesis(cfg); err != nil {
		return err
	}
	if err := WriteDockerCompose(root); err != nil {
		return err
	}
	if err := WriteTestnetScripts(root); err != nil {
		return err
	}
	if err := WriteCIWorkflow(root); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte(ReadmeMarkdown), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "ARCHITECTURE.md"), []byte(DocsArchitectureMarkdown), 0o644); err != nil {
		return err
	}
	return nil
}
