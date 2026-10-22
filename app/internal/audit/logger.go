package audit

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// SensitiveKeys lists field names that must NEVER be written in plaintext to logs
// (Acceptance Criterion #14).
var sensitiveKeys = []string{
	"password",
	"secret",
	"token",
	"cookie",
	"authorization",
	"assertion",
	"cf-access-jwt-assertion",
	"code_verifier",
	"pepper",
}

// Event represents an auditable authentication, authorization, or administrative action.
type Event struct {
	Timestamp      time.Time         `json:"timestamp"`
	EventType      string            `json:"event_type"`
	ActorSub       string            `json:"actor_sub"`
	ActorUsername  string            `json:"actor_username"`
	ActorRole      string            `json:"actor_role"`
	AccessIdentity string            `json:"access_identity"`
	ClientIP       string            `json:"client_ip"`
	TargetResource string            `json:"target_resource"`
	Outcome        string            `json:"outcome"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// DBRecorder persists audit events to PostgreSQL audit_logs table.
type DBRecorder interface {
	RecordAuditEvent(ctx context.Context, ev Event) error
}

// Logger writes structured JSON security audit events with mandatory secret scrubbing.
type Logger struct {
	mu  sync.Mutex
	out io.Writer
	db  DBRecorder
}

func NewLogger(out io.Writer, db DBRecorder) *Logger {
	if out == nil {
		out = os.Stdout
	}
	return &Logger{out: out, db: db}
}

// SanitizeMetadata scrubs any key whose name matches known sensitive patterns.
func SanitizeMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	clean := make(map[string]string, len(in))
	for k, v := range in {
		lower := strings.ToLower(k)
		redacted := false
		for _, bad := range sensitiveKeys {
			if strings.Contains(lower, bad) {
				clean[k] = "[REDACTED]"
				redacted = true
				break
			}
		}
		if !redacted {
			clean[k] = v
		}
	}
	return clean
}

func (l *Logger) Log(ctx context.Context, ev Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	ev.Metadata = SanitizeMetadata(ev.Metadata)

	l.mu.Lock()
	_ = json.NewEncoder(l.out).Encode(ev)
	l.mu.Unlock()

	if l.db != nil {
		_ = l.db.RecordAuditEvent(ctx, ev)
	}
}
