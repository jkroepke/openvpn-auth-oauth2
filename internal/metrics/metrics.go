package metrics

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const namespace = "openvpn_auth_oauth2_"

// ContentType is the Prometheus text exposition format version 0.0.4.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Results of a silent re-authentication attempt.
const (
	SilentReAuthSuccess  = "success"
	SilentReAuthFallback = "fallback"
	SilentReAuthError    = "error"
)

const (
	maxReasonLength = 64
	reasonOther     = "other"
)

// defaultBuckets are the Prometheus client default histogram buckets in seconds.
//
//nolint:gochecknoglobals
var defaultBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

// Metrics collects operational metrics of one daemon runtime and renders
// them in the Prometheus text exposition format.
//
// All methods are safe for concurrent use and accept a nil receiver, which
// disables recording.
type Metrics struct {
	clientDenied    *counterVec
	silentReAuth    *counterVec
	codeExchange    *histogram
	commandDuration *histogramVec
	version         string
	commit          string
	clientAccepted  atomic.Uint64
	clientQueue     atomic.Int64
}

// New returns an empty metrics collection. version and commit are exposed
// through the build info metric.
func New(version, commit string) *Metrics {
	return &Metrics{
		clientDenied:    newCounterVec(),
		silentReAuth:    newCounterVec(),
		codeExchange:    newHistogram(),
		commandDuration: newHistogramVec(),
		version:         version,
		commit:          commit,
	}
}

// ClientAccepted counts a client accepted on the OpenVPN management interface.
func (m *Metrics) ClientAccepted() {
	if m == nil {
		return
	}

	m.clientAccepted.Add(1)
}

// ClientDenied counts a client denied on the OpenVPN management interface.
// The reason is the deny.Reason text sent with client-deny. Any text that is
// not a plain phrase of ASCII letters, spaces and hyphens is reported as
// "other" to keep the label cardinality bounded.
func (m *Metrics) ClientDenied(reason string) {
	if m == nil {
		return
	}

	m.clientDenied.inc(normalizeReason(reason))
}

// SilentReAuth counts the result of a silent re-authentication attempt.
// result should be one of SilentReAuthSuccess, SilentReAuthFallback or SilentReAuthError.
func (m *Metrics) SilentReAuth(result string) {
	if m == nil {
		return
	}

	m.silentReAuth.inc(result)
}

// ObserveCodeExchange records the duration of a successful OAuth2 authorization code exchange.
func (m *Metrics) ObserveCodeExchange(d time.Duration) {
	if m == nil {
		return
	}

	m.codeExchange.observe(d.Seconds())
}

// ObserveCommand records the round-trip duration of a management interface command.
// command must be a command name from a fixed set, never user-controlled input.
func (m *Metrics) ObserveCommand(command string, d time.Duration) {
	if m == nil {
		return
	}

	m.commandDuration.observe(command, d.Seconds())
}

// ClientQueued increments the number of client events waiting for a worker.
func (m *Metrics) ClientQueued() {
	if m == nil {
		return
	}

	m.clientQueue.Add(1)
}

// ClientDequeued decrements the number of client events waiting for a worker.
func (m *Metrics) ClientDequeued() {
	if m == nil {
		return
	}

	m.clientQueue.Add(-1)
}

// ServeHTTP renders all metrics in the Prometheus text exposition format.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", ContentType)

	_ = m.Write(w)
}

// Write renders all metrics in the Prometheus text exposition format.
func (m *Metrics) Write(w io.Writer) error {
	if m == nil {
		return nil
	}

	buf := bufio.NewWriter(w)

	writeHeader(buf, "build_info", "gauge", "Build information about openvpn-auth-oauth2.")
	_, _ = fmt.Fprintf(buf, "%sbuild_info{version=\"%s\",commit=\"%s\",goversion=\"%s\"} 1\n",
		namespace, escapeLabel(m.version), escapeLabel(m.commit), escapeLabel(runtime.Version()))

	writeHeader(buf, "openvpn_client_accepted_total", "counter", "Total number of clients accepted on the OpenVPN management interface.")
	_, _ = fmt.Fprintf(buf, "%sopenvpn_client_accepted_total %d\n", namespace, m.clientAccepted.Load())

	writeHeader(buf, "openvpn_client_denied_total", "counter", "Total number of clients denied on the OpenVPN management interface, by reason.")
	m.clientDenied.write(buf, "openvpn_client_denied_total", "reason")

	writeHeader(buf, "oauth2_silent_reauth_total", "counter",
		"Total number of silent re-authentication attempts using a stored refresh token, by result.")
	m.silentReAuth.write(buf, "oauth2_silent_reauth_total", "result")

	writeHeader(buf, "oauth2_code_exchange_duration_seconds", "histogram",
		"Duration of successful OAuth2 authorization code exchanges, including token validation and userinfo requests.")
	m.codeExchange.write(buf, "oauth2_code_exchange_duration_seconds", "")

	writeHeader(buf, "openvpn_command_duration_seconds", "histogram", "Round-trip duration of answered commands sent to the OpenVPN management interface.")
	m.commandDuration.write(buf, "openvpn_command_duration_seconds", "command")

	writeHeader(buf, "openvpn_client_queue_length", "gauge", "Number of OpenVPN client events waiting for a worker.")
	_, _ = fmt.Fprintf(buf, "%sopenvpn_client_queue_length %d\n", namespace, m.clientQueue.Load())

	if err := buf.Flush(); err != nil {
		return fmt.Errorf("write metrics: %w", err)
	}

	return nil
}

func writeHeader(w io.Writer, name, metricType, help string) {
	_, _ = fmt.Fprintf(w, "# HELP %s%s %s\n# TYPE %s%s %s\n", namespace, name, help, namespace, name, metricType)
}

// normalizeReason converts fixed deny phrases into a snake_case label value.
// Any text with characters other than ASCII letters, spaces and hyphens is
// treated as dynamic and mapped to "other".
func normalizeReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > maxReasonLength {
		return reasonOther
	}

	var sb strings.Builder

	sb.Grow(len(reason))

	for _, char := range strings.ToLower(reason) {
		switch {
		case char >= 'a' && char <= 'z':
			sb.WriteRune(char)
		case char == ' ' || char == '-':
			sb.WriteByte('_')
		default:
			return reasonOther
		}
	}

	return sb.String()
}

func escapeLabel(value string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(value)
}

type counterVec struct {
	values map[string]uint64
	mu     sync.Mutex
}

func newCounterVec() *counterVec {
	return &counterVec{values: make(map[string]uint64)}
}

func (c *counterVec) inc(label string) {
	c.mu.Lock()
	c.values[label]++
	c.mu.Unlock()
}

func (c *counterVec) write(w io.Writer, name, labelName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, label := range sortedKeys(c.values) {
		_, _ = fmt.Fprintf(w, "%s%s{%s=\"%s\"} %d\n", namespace, name, labelName, escapeLabel(label), c.values[label])
	}
}

type histogram struct {
	counts []uint64
	sum    float64
	count  uint64
	mu     sync.Mutex
}

func newHistogram() *histogram {
	return &histogram{counts: make([]uint64, len(defaultBuckets))}
}

func (h *histogram) observe(value float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i, bound := range defaultBuckets {
		if value <= bound {
			h.counts[i]++
		}
	}

	h.sum += value
	h.count++
}

// write renders the histogram series. labels is either empty or a
// comma-terminated list of preformatted label pairs.
func (h *histogram) write(out io.Writer, name, labels string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i, bound := range defaultBuckets {
		_, _ = fmt.Fprintf(out, "%s%s_bucket{%sle=\"%s\"} %d\n", namespace, name, labels, strconv.FormatFloat(bound, 'g', -1, 64), h.counts[i])
	}

	_, _ = fmt.Fprintf(out, "%s%s_bucket{%sle=\"+Inf\"} %d\n", namespace, name, labels, h.count)

	labels = strings.TrimSuffix(labels, ",")
	if labels != "" {
		labels = "{" + labels + "}"
	}

	_, _ = fmt.Fprintf(out, "%s%s_sum%s %s\n", namespace, name, labels, strconv.FormatFloat(h.sum, 'g', -1, 64))
	_, _ = fmt.Fprintf(out, "%s%s_count%s %d\n", namespace, name, labels, h.count)
}

type histogramVec struct {
	values map[string]*histogram
	mu     sync.Mutex
}

func newHistogramVec() *histogramVec {
	return &histogramVec{values: make(map[string]*histogram)}
}

func (h *histogramVec) observe(label string, value float64) {
	h.mu.Lock()

	hist, ok := h.values[label]
	if !ok {
		hist = newHistogram()
		h.values[label] = hist
	}

	h.mu.Unlock()

	hist.observe(value)
}

func (h *histogramVec) write(w io.Writer, name, labelName string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, label := range sortedKeys(h.values) {
		h.values[label].write(w, name, fmt.Sprintf("%s=\"%s\",", labelName, escapeLabel(label)))
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}
