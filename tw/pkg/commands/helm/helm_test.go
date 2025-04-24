package helm_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/tw/pkg/commands/helm"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"helm-inventory": helm_inventory_main,
	})
}

func helm_inventory_main() {
	cmd := helm.Command()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestHelmInventory(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: filepath.Join("testdata", "helm-inventory"),
		Setup: func(e *testscript.Env) error {
			e.Vars = append(e.Vars,
				"HELM_CACHE_HOME=$WORK/helm-cache",
				"HELM_REPOSITORY_CACHE=$WORK/helm-cache",
				"HELM_CONFIG_HOME=$WORK/helm-config",
			)
			return nil
		},
	})
}
