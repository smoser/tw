package helm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/postrender"
	"helm.sh/helm/v3/pkg/release"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

const (
	DefaultTimeout = 5 * time.Minute
)

type cmdConfig struct {
	Name       string
	Namespace  string
	Chart      string
	Repo       string
	ValuePaths []string
	Out        string
}

func Command() *cobra.Command {
	cfg := &cmdConfig{}

	cmd := &cobra.Command{
		Use:  "whelm",
		Args: cobra.MinimumNArgs(2),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return cfg.preRun(cmd.Context(), args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cfg.Run(cmd.Context())
		},
	}

	cmd.Flags().StringVarP(&cfg.Namespace, "namespace", "n", "default", "namespace to install the release into")
	cmd.Flags().StringVarP(&cfg.Repo, "repo", "r", "", "chart repo")
	cmd.Flags().StringArrayVarP(&cfg.ValuePaths, "value", "f", []string{}, "path to a values file")
	cmd.Flags().StringVarP(&cfg.Out, "out", "o", "", "path to output file")

	return cmd
}

func (c *cmdConfig) Run(ctx context.Context) error {
	clog.InfoContext(ctx, "running whelm", "name", c.Name, "chart", c.Chart)

	settings := cli.New()
	acfg := new(action.Configuration)
	getters := getter.All(settings)

	v := values.Options{
		ValueFiles: []string{},
	}

	for _, vf := range c.ValuePaths {
		raw, err := os.ReadFile(c.Out)
		if err != nil {
			return fmt.Errorf("failed to read file: %v", err)
		}

		expanded := os.ExpandEnv(string(raw))

		// process the file and rewrite them to a temp file
		f, err := os.CreateTemp("", "tw-helm")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %v", err)
		}
		defer f.Close()

		if _, err := f.WriteString(expanded); err != nil {
			return fmt.Errorf("failed to write to temp file: %v", err)
		}

		clog.InfoContextf(ctx, "expanded %s to %s", vf, f.Name())
		v.ValueFiles = append(v.ValueFiles, f.Name())
	}

	vals, err := v.MergeValues(getters)
	if err != nil {
		return fmt.Errorf("failed to merge values: %v", err)
	}

	// if err := acfg.Init(settings.RESTClientGetter(), c.Namespace, "secret", ts.Logf); err != nil {
	if err := acfg.Init(settings.RESTClientGetter(), c.Namespace, "secret", nil); err != nil {
		return fmt.Errorf("failed to init action config: %v", err)
	}

	hc := action.NewHistory(acfg)
	_, err = hc.Run(c.Name)
	exists := err == nil

	var rel *release.Release

	if exists {
		clog.InfoContextf(ctx, "upgrading chart %s", c.Chart)

		action := action.NewUpgrade(acfg)
		action.Namespace = c.Namespace
		action.Wait = true
		action.WaitForJobs = true
		action.Timeout = DefaultTimeout
		action.ChartPathOptions.RepoURL = c.Repo
		action.PostRenderer = &foo{}

		cpath, err := action.ChartPathOptions.LocateChart(c.Chart, settings)
		if err != nil {
			return fmt.Errorf("failed to locate chart: %v", err)
		}

		chart, err := loader.Load(cpath)
		if err != nil {
			return fmt.Errorf("failed to load chart: %v", err)
		}

		r, err := action.RunWithContext(ctx, c.Name, chart, vals)
		if err != nil {
			return fmt.Errorf("failed to run helm install: %v", err)
		}
		rel = r

	} else {
		clog.InfoContextf(ctx, "installing chart %s", c.Chart)

		action := action.NewInstall(acfg)
		action.ReleaseName = c.Name
		action.Namespace = c.Namespace
		action.CreateNamespace = true
		action.Wait = true
		action.WaitForJobs = true
		action.Timeout = DefaultTimeout
		action.ChartPathOptions.RepoURL = c.Repo
		action.PostRenderer = &foo{}

		cpath, err := action.ChartPathOptions.LocateChart(c.Chart, settings)
		if err != nil {
			return fmt.Errorf("failed to locate chart: %v", err)
		}

		chart, err := loader.Load(cpath)
		if err != nil {
			return fmt.Errorf("failed to load chart: %v", err)
		}

		r, err := action.RunWithContext(ctx, chart, vals)
		if err != nil {
			return fmt.Errorf("failed to run helm install: %v", err)
		}
		rel = r
	}

	clog.InfoContextf(ctx, "finished releasing: %s", rel.Name)

	return nil
}

func (c *cmdConfig) preRun(ctx context.Context, args []string) error {
	c.Name = args[0]
	c.Chart = args[1]
	return nil
}

type foo struct{}

// Run implements postrender.PostRenderer.
func (f *foo) Run(renderedManifests *bytes.Buffer) (modifiedManifests *bytes.Buffer, err error) {
	fmt.Println("waddup buttercup")

	out := bytes.NewBuffer(nil)
	decoder := yaml.NewDecoder(renderedManifests)
	encoder := yaml.NewEncoder(out)

	for {
		var obj unstructured.Unstructured
		if err := decoder.Decode(&obj.Object); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to decode: %v", err)
		}

		if len(obj.Object) == 0 {
			continue
		}

		labels := obj.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		labels["imagetest"] = "true"
		fmt.Fprintf(os.Stderr, "-- labels: %v\n", labels)
		obj.SetLabels(map[string]string{})

		if err := encoder.Encode(&obj.Object); err != nil {
			return nil, fmt.Errorf("failed to encode: %v", err)
		}
	}

	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("failed to close encoder: %v", err)
	}

	return out, nil
}

var _ postrender.PostRenderer = &foo{}
