package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

//
// ======================= FLAGS (replace env vars) =======================
//
var (
	addr            = flag.String("addr", ":8080", "Listen address (e.g., :8080 or 0.0.0.0:8080)")
	apiKey          = flag.String("api-key", "", "API key required in X-API-Key for /api/ endpoints (recommended)")
	logFile         = flag.String("log-file", defaultLogPath(), "Path to JSONL event log (always written)")
	prettyToStdout  = flag.Bool("pretty", false, "Print pretty (colorized) event lines to stdout (stderr if false)")
	mirrorJSONToStd = flag.Bool("json-stdout", true, "Also echo each JSON event to stdout")
	redirectURL     = flag.String("redirect-url", "https://example.com", "Target URL for link tokens (/l/{id})")
	allowCORS       = flag.Bool("allow-cors", false, "Set basic CORS headers for /api endpoints")
	aliasRoutes     = flag.Bool("alias-routes", true, "Also serve /p/{id}.png and /t/{id} aliases")
	behindProxy     = flag.Bool("behind-proxy", true, "Trust X-Forwarded-For for client IP")
)

func defaultLogPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(`C:\canary`, "canary_token.jsonl")
	}
	return "/var/log/canary/canary_token.jsonl"
}

//
// ======================= TYPES =======================
//
type Token struct {
	ID     string    `json:"id"`
	Type   string    `json:"type"` // "pixel" | "link" | "qr" | etc. (we mainly use pixel/link here)
	Label  string    `json:"label,omitempty"`
	Note   string    `json:"note,omitempty"`
	Secret string    `json:"secret,omitempty"`
	At     time.Time `json:"created_at"`
}

type Event struct {
	TokenID   string    `json:"token_id"`
	Kind      string    `json:"kind"` // "pixel" | "link" | ...
	RemoteIP  string    `json:"remote_ip"`
	UserAgent string    `json:"user_agent"`
	At        time.Time `json:"at"`
	Meta      any       `json:"meta,omitempty"`
}

type tokenReq struct {
	ID, Type, Label, Note, Secret string
}

type tokenResp struct {
	ID string `json:"id"`
}

type Store struct {
	mu     sync.RWMutex
	tokens map[string]Token
}

func NewStore() *Store {
	return &Store{tokens: make(map[string]Token)}
}

func (s *Store) PutToken(t Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.ID] = t
}

func (s *Store) GetToken(id string) (Token, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[id]
	return t, ok
}

//
// ======================= JSON LOGGER (ALWAYS WRITES) =======================
//
type JSONLogger struct {
	mu sync.Mutex
	f  *os.File
}

func NewJSONLogger(path string) (*JSONLogger, error) {
	// Ensure directory exists
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create log dir %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file %q: %w", path, err)
	}
	return &JSONLogger{f: f}, nil
}

func (l *JSONLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}

func (l *JSONLogger) LogJSON(v any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = l.f.Write(b)
	return err
}

//
// ======================= PRETTY PRINT =======================
//
func prettyLine(ev Event) string {
	// Cyberpunk-ish without external deps
	// [EVENT] <kind> id=<id> ip=[x] ua="..." at=RFC3339
	var b strings.Builder
	fmt.Fprintf(&b, "\x1b[38;5;199m[EVENT]\x1b[0m ")
	fmt.Fprintf(&b, "\x1b[38;5;45m%s\x1b[0m ", ev.Kind)     // cyan
	fmt.Fprintf(&b, "id=\x1b[38;5;214m%s\x1b[0m ", ev.TokenID) // orange
	fmt.Fprintf(&b, "ip=[%s] ", ev.RemoteIP)
	fmt.Fprintf(&b, "ua=\"%s\" ", truncate(ev.UserAgent, 140))
	fmt.Fprintf(&b, "at=%s", ev.At.UTC().Format(time.RFC3339))
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

//
// ======================= EMIT EVENT (single place) =======================
// Always writes JSON to file; optional JSON stdout; pretty to stdout/stderr.
//
func emitEvent(jl *JSONLogger, ev Event) {
	// Always write JSON to file.
	if err := jl.LogJSON(ev); err != nil {
		log.Printf("ERROR writing event to log: %v", err)
	}

	// Optionally mirror JSON to stdout.
	if *mirrorJSONToStd {
		if b, err := json.Marshal(ev); err == nil {
			fmt.Fprintln(os.Stdout, string(b))
		}
	}

	// Pretty line.
	line := prettyLine(ev)
	if *prettyToStdout {
		fmt.Fprintln(os.Stdout, line)
	} else {
		fmt.Fprintln(os.Stderr, line)
	}
}

//
// ======================= HELPERS =======================
//
func clientIP(r *http.Request) string {
	// best-effort: use X-Forwarded-For when behind proxy, else RemoteAddr
	if *behindProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			parts := strings.Split(xf, ",")
			return strings.TrimSpace(parts[0])
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func mustAPIKey(r *http.Request) error {
	if *apiKey == "" {
		// if not set, permit (but warn once)
		return nil
	}
	k := r.Header.Get("X-API-Key")
	if subtleConstTimeEq(k, *apiKey) {
		return nil
	}
	return errors.New("unauthorized")
}

func subtleConstTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func writeCORS(w http.ResponseWriter, r *http.Request) bool {
	if !*allowCORS {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

func randID(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

//
// ======================= HTTP HANDLERS =======================
//
func apiCreateToken(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if *allowCORS && writeCORS(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := mustAPIKey(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req tokenReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Type) == "" {
			http.Error(w, "missing type", http.StatusBadRequest)
			return
		}
		id := req.ID
		if id == "" {
			id = randID(10)
		}
		tok := Token{
			ID:     id,
			Type:   req.Type,
			Label:  strings.TrimSpace(req.Label),
			Note:   strings.TrimSpace(req.Note),
			Secret: strings.TrimSpace(req.Secret),
			At:     time.Now().UTC(),
		}
		s.PutToken(tok)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResp{ID: id})
	}
}

func handlePixel(s *Store, jl *JSONLogger) http.HandlerFunc {
	oneByOnePNG := []byte{
		137, 80, 78, 71, 13, 10, 26, 10,
		0, 0, 0, 13, 73, 72, 68, 82,
		0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 31, 21, 196, 137,
		0, 0, 0, 12, 73, 68, 65, 84, 120, 156, 99, 248, 15, 4, 0, 9, 251, 3, 253, 167, 42, 147, 25,
		0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/pixel/")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		// It’s okay if token is unknown; we still record the event.
		ev := Event{
			TokenID:   id,
			Kind:      "pixel",
			RemoteIP:  clientIP(r),
			UserAgent: r.UserAgent(),
			At:        time.Now().UTC(),
		}
		emitEvent(jl, ev)

		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(oneByOnePNG)
	}
}

func handleLink(s *Store, jl *JSONLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/l/")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		ev := Event{
			TokenID:   id,
			Kind:      "link",
			RemoteIP:  clientIP(r),
			UserAgent: r.UserAgent(),
			At:        time.Now().UTC(),
		}
		emitEvent(jl, ev)
		http.Redirect(w, r, *redirectURL, http.StatusFound)
	}
}

// Aliases to match generator output: /p/{id}.png and /t/{id}
func handlePixelAlias(s *Store, jl *JSONLogger) http.HandlerFunc {
	oneByOnePNG := []byte{
		137, 80, 78, 71, 13, 10, 26, 10,
		0, 0, 0, 13, 73, 72, 68, 82,
		0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 31, 21, 196, 137,
		0, 0, 0, 12, 73, 68, 65, 84, 120, 156, 99, 248, 15, 4, 0, 9, 251, 3, 253, 167, 42, 147, 25,
		0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/p/")
		id := strings.TrimSuffix(path, ".png")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		ev := Event{
			TokenID:   id,
			Kind:      "pixel",
			RemoteIP:  clientIP(r),
			UserAgent: r.UserAgent(),
			At:        time.Now().UTC(),
		}
		emitEvent(jl, ev)
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(oneByOnePNG)
	}
}

func handleLinkAlias(s *Store, jl *JSONLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/t/")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		ev := Event{
			TokenID:   id,
			Kind:      "link",
			RemoteIP:  clientIP(r),
			UserAgent: r.UserAgent(),
			At:        time.Now().UTC(),
		}
		emitEvent(jl, ev)
		http.Redirect(w, r, *redirectURL, http.StatusFound)
	}
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

//
// ======================= MAIN =======================
//
func main() {
	rand.Seed(time.Now().UnixNano())
	flag.Parse()

	// Initialize persistent JSON logger (fail fast if not writable).
	jl, err := NewJSONLogger(*logFile)
	if err != nil {
		log.Fatalf("failed to initialize log file: %v", err)
	}
	defer jl.Close()

	store := NewStore()

	mux := http.NewServeMux()

	// API
	mux.HandleFunc("/api/tokens", func(w http.ResponseWriter, r *http.Request) {
		if *allowCORS && r.Method == http.MethodOptions {
			writeCORS(w, r)
			return
		}
		if *allowCORS {
			writeCORS(w, r)
		}
		if err := mustAPIKey(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			apiCreateToken(store).ServeHTTP(w, r)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	// Beacon endpoints
	mux.HandleFunc("/pixel/", handlePixel(store, jl))
	mux.HandleFunc("/l/", handleLink(store, jl))

	// Optional aliases for generator defaults
	if *aliasRoutes {
		mux.HandleFunc("/p/", handlePixelAlias(store, jl))
		mux.HandleFunc("/t/", handleLinkAlias(store, jl))
	}

	// Health
	mux.HandleFunc("/healthz", handleHealthz)

	log.Printf("canary server listening on %s, logging to %s", *addr, *logFile)
	if *apiKey == "" {
		log.Printf("WARNING: --api-key is empty; /api/ endpoints are unauthenticated")
	}
	log.Printf("redirect target for /l and /t: %s", *redirectURL)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
