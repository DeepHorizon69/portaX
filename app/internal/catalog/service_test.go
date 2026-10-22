package catalog

import "testing"

func TestValidateLaunchURLBlocksXSSAndPrivateIPs(t *testing.T) {
	suffixes := []string{"alsa.web.id", "ts.net"}

	validURLs := []string{
		"https://pihole.alsa.web.id/admin",
		"https://proxmox.tail1234.ts.net:8006/",
	}
	for _, u := range validURLs {
		if err := ValidateLaunchURL(u, suffixes); err != nil {
			t.Fatalf("expected valid launch URL %q to pass, got: %v", u, err)
		}
	}

	maliciousURLs := []string{
		"javascript:alert(document.cookie)",
		"data:text/html,<script>alert(1)</script>",
		"http://pihole.alsa.web.id/admin",           // plaintext HTTP rejected by default
		"https://admin:secret@pihole.alsa.web.id/",  // embedded credentials rejected
		"https://192.168.1.10:8006/",                // raw RFC1918 IP literal rejected
		"https://169.254.169.254/latest/meta-data/", // cloud metadata IP rejected
		"https://[::1]:8080/",                       // IPv6 loopback rejected
		"https://evil.example.com/phish",            // unapproved domain rejected
	}
	for _, bad := range maliciousURLs {
		if err := ValidateLaunchURL(bad, suffixes); err == nil {
			t.Fatalf("expected malicious/invalid URL %q to be rejected", bad)
		}
	}
}
