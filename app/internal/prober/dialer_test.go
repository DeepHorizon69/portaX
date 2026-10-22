package prober

import "testing"

func TestSSRFGuardSocketValidation(t *testing.T) {
	allowedNets, err := parseCIDRs([]string{"192.168.1.0/24", "100.64.0.0/10"})
	if err != nil {
		t.Fatalf("parse cidrs: %v", err)
	}

	// 1. Valid LAN and Tailscale IPs must be permitted
	validAddrs := []string{
		"192.168.1.50:443",
		"100.101.102.103:8006",
	}
	for _, addr := range validAddrs {
		if err := ValidateSocketIP(addr, allowedNets); err != nil {
			t.Fatalf("expected allowed IP %q to pass, got: %v", addr, err)
		}
	}

	// 2. SSRF targets (Metadata, Loopback, Internal Docker Bridges, Unlisted subnets) MUST be blocked
	blockedAddrs := []string{
		"127.0.0.1:8080",       // Loopback
		"[::1]:8080",           // IPv6 Loopback
		"169.254.169.254:80",   // Cloud Metadata endpoint
		"172.30.3.4:5432",      // portaX internal portal-db IP
		"172.30.4.4:5432",      // portaX internal authentik-db IP
		"172.30.1.2:8081",      // portaX internal Caddy OIDC backchannel listener
		"10.0.0.15:443",        // RFC1918 subnet not in target's allowed_cidrs
		"0.0.0.0:80",           // Unspecified address
	}
	for _, bad := range blockedAddrs {
		if err := ValidateSocketIP(bad, allowedNets); err == nil {
			t.Fatalf("SSRF guard failed to block forbidden socket destination %q", bad)
		}
	}
}
