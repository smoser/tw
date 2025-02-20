package ksnap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

const (
	DefaultTimeout = 5 * time.Minute
)

type cmdConfig struct {
	Namespace string
	OutPath   string

	clientset *kubernetes.Clientset
}

func Command() *cobra.Command {
	cfg := &cmdConfig{}

	cmd := &cobra.Command{
		Use:   "ksnap",
		Short: "Simple kubernetes snapshot testing",
		Args:  cobra.MinimumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return cfg.prerun(cmd.Context())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "images":
				cfg.RunImages(cmd.Context())
			default:
				return fmt.Errorf("unknown subcommand: %s", args[0])
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&cfg.Namespace, "namespace", "n", "", "namespace to snapshot")
	cmd.Flags().StringVarP(&cfg.OutPath, "out", "o", "", "path to output file")

	return cmd
}

func (c *cmdConfig) RunImages(ctx context.Context) error {
	pods, err := c.clientset.CoreV1().Pods(c.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list pods: %v", err)
	}

	images := ImagesSnapshot{}
	for _, pod := range pods.Items {
		clog.InfoContextf(ctx, "pod: %s", pod.Name)

		for _, c := range pod.Spec.Containers {
			clog.InfoContextf(ctx, "container: %s", c.Name)

			ref, err := name.ParseReference(c.Image)
			if err != nil {
				return fmt.Errorf("failed to parse image reference: %v", err)
			}

			images[ref.Context().String()] = ImageSnapshot{
				Context:       ref.Context().String(),
				Identifier:    ref.Identifier(),
				ContainerName: c.Name,
				Namespace:     pod.Namespace,
			}
		}
	}

	f, err := os.Create(c.OutPath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", c.OutPath, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(images); err != nil {
		return fmt.Errorf("failed to encode json: %v", err)
	}

	clog.InfoContextf(ctx, "images: %v", images)
	return nil
}

type ImagesSnapshot map[string]ImageSnapshot

// ImageSnapshot is the relevant fields we want to snapshot
type ImageSnapshot struct {
	// These are terrible names but I blame whoever wrote ggcr
	Context       string `json:"context"`
	Identifier    string `json:"identifier"`
	ContainerName string `json:"container_name"`
	Namespace     string `json:"pod_namespace"`
}

func (c *cmdConfig) prerun(_ context.Context) error {
	getter := genericclioptions.NewConfigFlags(false)

	cfg, err := getter.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to get rest config: %v", err)
	}

	c.clientset, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %v", err)
	}

	return nil
}
