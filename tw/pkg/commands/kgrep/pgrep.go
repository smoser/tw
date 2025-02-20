package kgrep

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/polymorphichelpers"
)

const (
	DefaultTimeout = 5 * time.Second
)

type cfg struct {
	Name       string
	Namespace  string
	Timeout    time.Duration
	IgnoreCase bool
	Container  string
	Retry      int

	names       []string
	matchText   string
	compiled    *regexp.Regexp
	highlighter func(string) string
}

func Command() *cobra.Command {
	cfg := &cfg{}

	cmd := &cobra.Command{
		Use:          "kgrep",
		Short:        "Simple kubernetes pod grepping",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return cfg.prerun(cmd.Context(), args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cfg.Run(cmd)
		},
	}

	cmd.Flags().StringVarP(&cfg.Namespace, "namespace", "n", "", "namespace to install the release into")
	cmd.Flags().DurationVarP(&cfg.Timeout, "timeout", "t", DefaultTimeout, "time to wait for logs to appear")
	cmd.Flags().IntVarP(&cfg.Retry, "retry", "r", 0, "number of times to retry a failed request")
	cmd.Flags().BoolVarP(&cfg.IgnoreCase, "ignore-case", "i", false, "toggle to ignore case for the match")
	cmd.Flags().StringVarP(&cfg.Container, "container", "c", "", "container to grep logs from (if not specified, will search in all)")

	return cmd
}

func (c *cfg) Run(cmd *cobra.Command) error {
	ctx := cmd.Context()

	l := clog.FromContext(ctx).With("resource", c.names, "namespace", c.Namespace)
	l.InfoContext(ctx, "running kgrep", "match", c.matchText)

	attempt := 0
	err := wait.ExponentialBackoffWithContext(ctx, wait.Backoff{
		Steps:    c.Retry + 1,
		Duration: c.Timeout,
		Factor:   1.0, // Keep backoff linear
	}, func(ctx context.Context) (bool, error) {
		attempt++

		if err := c.retryableRun(ctx); err != nil {
			l.ErrorContextf(ctx, "[%d/%d] failed to run kgrep: %v", attempt, c.Retry+1, err)
			return false, nil
		}

		l.InfoContext(ctx, "kgrep succeeded", "attempt", attempt, "timeout", c.Timeout)
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("kgrep failed after %d attempt(s)", attempt)
	}

	return nil
}

func (c *cfg) retryableRun(ctx context.Context) error {
	getter := genericclioptions.NewConfigFlags(false)

	infos, err := util.NewFactory(getter).NewBuilder().
		WithScheme(scheme.Scheme, scheme.Scheme.PrioritizedVersionsAllGroups()...).
		NamespaceParam(c.Namespace).
		DefaultNamespace().
		SingleResourceType().
		ResourceNames(c.names[0], c.names[1:]...).
		Do().Infos()
	if err != nil {
		return fmt.Errorf("failed to get infos: %v", err)
	}

	if len(infos) != 1 {
		return fmt.Errorf("expected 1 info, got %d", len(infos))
	}

	lopts := &corev1.PodLogOptions{}
	if c.Container != "" {
		lopts.Container = c.Container
	}
	lall := lopts.Container == ""

	reqs, err := polymorphichelpers.LogsForObjectFn(getter, infos[0].Object, lopts, 10*time.Second, lall)
	if err != nil {
		return fmt.Errorf("failed to get logs: %v", err)
	}

	matches := []match{}
	for obj, req := range reqs {
		stream, err := req.Stream(ctx)
		if err != nil {
			return fmt.Errorf("failed to stream logs: %v", err)
		}
		defer stream.Close()

		scanner := bufio.NewScanner(stream)
		for scanner.Scan() {
			matchText, matched := c.matched(scanner.Text())
			if matched {
				matches = append(matches, match{
					Name:      obj.Name,
					Namespace: obj.Namespace,
					Text:      matchText,
				})
			}
		}
	}

	nmatches := len(matches)

	if nmatches == 0 {
		return fmt.Errorf("no match found for pattern: %s", c.matchText)
	}

	clog.InfoContextf(ctx, "found %d matches in %s", nmatches, infos[0].String())
	for i, m := range matches {
		clog.InfoContextf(ctx, "-- [%d/%d] in %s/%s: %s", i+1, nmatches, m.Name, m.Namespace, m.Text)
	}

	return nil
}

func (c *cfg) prerun(_ context.Context, args []string) error {
	c.names = strings.Split(args[0], "/")

	if args[1] == "" {
		return fmt.Errorf("expected a match pattern")
	}
	c.matchText = args[1]

	p := args[1]
	if c.IgnoreCase {
		p = "(?i)" + p
	}
	c.compiled = regexp.MustCompile(p)

	c.highlighter = func(s string) string {
		if isatty.IsTerminal(os.Stdout.Fd()) {
			return "\x1b[32;1m" + s + "\x1b[0m"
		}
		return "( " + s + " )"
	}
	return nil
}

type match struct {
	Name      string
	Namespace string
	Text      string
}

func (c *cfg) matched(line string) (string, bool) {
	if !c.compiled.MatchString(line) {
		return "", false
	}
	return c.compiled.ReplaceAllStringFunc(line, c.highlighter), true
}
