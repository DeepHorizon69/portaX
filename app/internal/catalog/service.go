package catalog

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	slugRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

	// AllowedIcons is the static build-time allowlist of icons.
	// Custom uploads and remote icon URLs are prohibited (Flaw 5 mitigation).
	AllowedIcons = map[string]bool{
		"shield":   true,
		"server":   true,
		"database": true,
		"network":  true,
		"cloud":    true,
		"terminal": true,
		"lock":     true,
		"activity": true,
		"globe":    true,
		"cpu":      true,
	}

	AllowedProtectionModes = map[string]bool{
		"cloudflare_access":      true,
		"authentik_forward_auth": true,
		"tailscale_only":         true,
	}
)

// Item represents a homelab service in the portal catalog.
// Notice: Internal probe hosts/IPs are NEVER stored on or serialized from Item.
type Item struct {
	ID              string    `json:"id"`
	DisplayName     string    `json:"display_name"`
	Description     string    `json:"description"`
	Category        string    `json:"category"`
	IconKey         string    `json:"icon_key"`
	LaunchURL       string    `json:"launch_url"`
	ProtectionMode  string    `json:"protection_mode"`
	AllowedRoles    []string  `json:"allowed_roles"`
	ProbeTargetID   string    `json:"probe_target_id,omitempty"`
	MaintenanceMode bool      `json:"maintenance_mode"`
	MaintenanceNote string    `json:"maintenance_note,omitempty"`
	StatusState     string    `json:"status_state"`
	LatencyMS       int       `json:"latency_ms"`
	CheckedAt       time.Time `json:"checked_at,omitempty"`
}

// ValidateItem strictly validates a catalog item before database insertion or update.
// Prevents XSS schemes (javascript:, data:, vbscript:), credential leaks in URLs,
// raw IP literals, and unapproved hostnames.
func ValidateItem(it Item, allowedHostSuffixes []string, validProbeTargets map[string]bool) error {
	if !slugRegex.MatchString(it.ID) {
		return errors.New("invalid service id slug (must be 2-63 lowercase alphanumeric or hyphens)")
	}
	if l := len(strings.TrimSpace(it.DisplayName)); l < 1 || l > 80 {
		return errors.New("display_name must be 1..80 characters")
	}
	if l := len(strings.TrimSpace(it.Description)); l < 1 || l > 280 {
		return errors.New("description must be 1..280 characters")
	}
	if l := len(strings.TrimSpace(it.Category)); l < 1 || l > 40 {
		return errors.New("category must be 1..40 characters")
	}
	if !AllowedIcons[it.IconKey] {
		return fmt.Errorf("icon_key %q is not in the static bundled icon allowlist", it.IconKey)
	}
	if !AllowedProtectionModes[it.ProtectionMode] {
		return fmt.Errorf("protection_mode %q is invalid", it.ProtectionMode)
	}
	if err := ValidateLaunchURL(it.LaunchURL, allowedHostSuffixes); err != nil {
		return err
	}
	if len(it.AllowedRoles) == 0 {
		return errors.New("allowed_roles cannot be empty")
	}
	for _, r := range it.AllowedRoles {
		if r != "viewer" && r != "admin" {
			return fmt.Errorf("invalid role %q in allowed_roles", r)
		}
	}
	if it.ProbeTargetID != "" && validProbeTargets != nil {
		if !validProbeTargets[it.ProbeTargetID] {
			return fmt.Errorf("probe_target_id %q does not exist in Git-managed targets.yaml allowlist", it.ProbeTargetID)
		}
	}
	return nil
}

// ValidateLaunchURL enforces HTTPS, rejects userinfo, rejects IP literals, and checks host suffixes.
func ValidateLaunchURL(raw string, allowedHostSuffixes []string) error {
	if len(raw) < 8 || len(raw) > 512 {
		return errors.New("launch_url length must be between 8 and 512 characters")
	}
	if strings.ContainsAny(raw, " \t\r\n<>\"'`") {
		return errors.New("launch_url contains forbidden characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("malformed launch_url")
	}
	if u.Scheme != "https" {
		return errors.New("launch_url must use https scheme")
	}
	if u.User != nil {
		return errors.New("launch_url must not contain userinfo credentials")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return errors.New("launch_url must include a valid hostname")
	}
	if net.ParseIP(host) != nil || strings.HasPrefix(host, "[") {
		return errors.New("launch_url must not expose raw IP addresses; use Access or MagicDNS hostnames")
	}

	matched := false
	for _, suffix := range allowedHostSuffixes {
		s := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(suffix, ".")))
		if s == "" {
			continue
		}
		if host == s || strings.HasSuffix(host, "."+s) {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("launch_url hostname %q does not match allowed suffixes", host)
	}
	return nil
}

// FilterForRole returns only the catalog items that the user's server-side role is permitted to view.
func FilterForRole(items []Item, userRole string) []Item {
	if userRole == "" {
		return nil
	}
	out := make([]Item, 0, len(items))
	for _, it := range items {
		for _, allowed := range it.AllowedRoles {
			if allowed == userRole || userRole == "admin" {
				out = append(out, it)
				break
			}
		}
	}
	return out
}
