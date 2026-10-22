package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alsa/portax/internal/db"
	"github.com/alsa/portax/internal/prober"
	"gopkg.in/yaml.v3"
)

type targetsFile struct {
	Targets []prober.Target `yaml:"targets"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	targetsPath := envOr("TARGETS_FILE", "/etc/portax/targets.yaml")
	interval, err := time.ParseDuration(envOr("PROBE_INTERVAL", "30s"))
	if err != nil || interval < 30*time.Second {
		// Enforce minimum 30-second probe interval
		interval = 30 * time.Second
	}

	store, err := db.ConnectPool(
		ctx,
		envOr("DB_HOST", "172.30.3.4"),
		envOr("DB_PORT", "5432"),
		envOr("DB_NAME", "portax"),
		envOr("DB_USER", "portal_prober"),
		envOr("DB_PASSWORD_FILE", "/run/secrets/portal_db_prober_password"),
		4,
	)
	if err != nil {
		os.Exit(1)
	}
	defer store.Close()

	runCycle(ctx, targetsPath, store)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runCycle(ctx, targetsPath, store)
		}
	}
}

func runCycle(ctx context.Context, path string, store *db.Store) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var tf targetsFile
	if err := yaml.Unmarshal(raw, &tf); err != nil {
		return
	}

	// Bounded concurrency: max 4 worker goroutines
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup

	for _, t := range tf.Targets {
		if t.ID == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target prober.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			res := prober.Probe(probeCtx, target)
			_ = store.UpsertProbeResult(ctx, res)
		}(t)
	}

	wg.Wait()
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
