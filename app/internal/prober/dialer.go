package prober

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"syscall"
	"time"
)

var (
	ErrSSRFBlocked = errors.New("ssrf guard blocked target IP address")
)

// alwaysDeniedCIDRs lists IP ranges that the prober must NEVER connect to,
// even if a DNS record or rebinding attack resolves a hostname to them.
var alwaysDeniedCIDRs = mustParseCIDRs([]string{
	"0.0.0.0/8",          // "This" network
	"127.0.0.0/8",        // IPv4 Loopback
	"169.254.0.0/16",     // Cloud metadata & IPv4 link-local
	"172.30.0.0/21",      // portaX internal Docker bridge networks
	"224.0.0.0/4",        // Multicast
	"240.0.0.0/4",        // Reserved
	"::1/128",            // IPv6 Loopback
	"fe80::/10",          // IPv6 Link-local
	"ff00::/8",           // IPv6 Multicast
	"fc00::/7",           // IPv6 Unique Local
})

// Target defines a single allowlisted health-check destination from targets.yaml.
type Target struct {
	ID             string   `yaml:"id"`
	Method         string   `yaml:"method"` // "https_get", "http_get", "tcp"
	Host           string   `yaml:"host"`
	Port           int      `yaml:"port"`
	Path           string   `yaml:"path"`
	ExpectedStatus int      `yaml:"expected_status"`
	AllowedCIDRs   []string `yaml:"allowed_cidrs"`
	TLSVerify      bool     `yaml:"tls_verify"`
}

// Result contains only sanitized health status metadata safe for DB storage.
type Result struct {
	TargetID   string
	State      string // "up", "down", "degraded"
	LatencyMS  int
	ReasonCode string // "ok", "timeout", "tls_error", "unexpected_status", "unreachable", "ssrf_blocked"
	CheckedAt  time.Time
}

// ValidateSocketIP is executed inside net.Dialer.Control (zero-TOCTOU DNS rebinding defense).
// The network string is "tcp4" or "tcp6", and address is the resolved "ip:port" right before connect().
func ValidateSocketIP(address string, allowedNets []*net.IPNet) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: invalid host:port %q", ErrSSRFBlocked, address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: unparseable IP %q", ErrSSRFBlocked, host)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("%w: loopback/link-local/unspecified IP %s denied", ErrSSRFBlocked, ip.String())
	}

	for _, denied := range alwaysDeniedCIDRs {
		if denied.Contains(ip) {
			return fmt.Errorf("%w: IP %s is in mandatory deny CIDR %s", ErrSSRFBlocked, ip.String(), denied.String())
		}
	}

	if len(allowedNets) == 0 {
		return fmt.Errorf("%w: empty allowed_cidrs for target", ErrSSRFBlocked)
	}
	for _, allowed := range allowedNets {
		if allowed.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("%w: IP %s not in target allowed_cidrs", ErrSSRFBlocked, ip.String())
}

// NewSafeDialer builds a net.Dialer that enforces ValidateSocketIP at the raw socket level.
func NewSafeDialer(allowedCIDRs []string) (*net.Dialer, error) {
	allowedNets, err := parseCIDRs(allowedCIDRs)
	if err != nil {
		return nil, err
	}
	return &net.Dialer{
		Timeout:   2 * time.Second,
		KeepAlive: -1,
		Control: func(network, address string, c syscall.RawConn) error {
			return ValidateSocketIP(address, allowedNets)
		},
	}, nil
}

// Probe executes a single bounded, SSRF-safe health check for the given Target.
func Probe(ctx context.Context, t Target) Result {
	start := time.Now()
	res := Result{
		TargetID:   t.ID,
		State:      "down",
		ReasonCode: "unreachable",
		CheckedAt:  start.UTC(),
	}

	dialer, err := NewSafeDialer(t.AllowedCIDRs)
	if err != nil {
		res.ReasonCode = "ssrf_blocked"
		return res
	}

	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	if t.Method == "tcp" {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		res.LatencyMS = int(time.Since(start).Milliseconds())
		if err != nil {
			if errors.Is(err, ErrSSRFBlocked) {
				res.ReasonCode = "ssrf_blocked"
			}
			return res
		}
		_ = conn.Close()
		res.State = "up"
		res.ReasonCode = "ok"
		return res
	}

	scheme := "https"
	if t.Method == "http_get" {
		scheme = "http"
	}
	path := t.Path
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	targetURL := scheme + "://" + addr + path

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		DisableCompression:    true, // Mitigates gzip bomb DoS (Flaw 6)
		MaxResponseHeaderBytes: 4096,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         t.Host,
			InsecureSkipVerify: !t.TLSVerify,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		// Never follow redirects (prevents open-redirect SSRF pivot)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return res
	}
	req.Header.Set("User-Agent", "portaX-prober/1.0")

	resp, err := client.Do(req)
	res.LatencyMS = int(time.Since(start).Milliseconds())
	if err != nil {
		if errors.Is(err, ErrSSRFBlocked) {
			res.ReasonCode = "ssrf_blocked"
		} else if errors.Is(err, context.DeadlineExceeded) {
			res.ReasonCode = "timeout"
		}
		return res
	}
	defer resp.Body.Close()

	// Read at most 4 KB and discard immediately
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	expected := t.ExpectedStatus
	if expected == 0 {
		expected = http.StatusOK
	}
	if resp.StatusCode == expected {
		res.State = "up"
		res.ReasonCode = "ok"
	} else {
		res.State = "degraded"
		res.ReasonCode = "unexpected_status"
	}
	return res
}

func parseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		return nil, errors.New("empty CIDR list")
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	nets, err := parseCIDRs(cidrs)
	if err != nil {
		panic(err)
	}
	return nets
}
