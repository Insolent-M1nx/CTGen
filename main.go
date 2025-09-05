package main

import (
	"embed"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// =========================
// Types & in-memory store
// =========================

type Token struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "url" | "pixel" | "qr" | "dns"
	Label     string    `json:"label"`
	Note      string    `json:"note"`
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
}

type Event struct {
	TokenID   string    `json:"token_id"`
	Kind      string    `json:"kind"` // "link" | "pixel" | "qr" | "dns"
	RemoteIP  string    `json:"remote_ip"`
	UserAgent string    `json:"user_agent"`
	At        time.Time `json:"at"`
	Name      string    `json:"name,omitempty"` // for DNS queries
}

type memoryStore struct {
	mu     sync.Mutex
	tokens map[string]Token
	events []Event
}

func newStore() *memoryStore { return &memoryStore{tokens: map[string]Token{}} }

func (s *memoryStore) addToken(t Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.ID] = t
}

func (s *memoryStore) getToken(id string) (Token, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	return t, ok
}

func (s *memoryStore) addEvent(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *memoryStore) listEvents(id string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, e := range s.events {
		if e.TokenID == id {
			out = append(out, e)
		}
	}
	return out
}

// =========================
// Embedded static page
// =========================

//go:embed index.html
var indexHTML embed.FS

// =========================
// Main
// =========================

func main() {
	addr := env("ADDR", ":8080")
	apiKey := env("API_KEY", "changeme")

	// Optional DNS listener (authoritative) for DNS tokens
	// Example: DNS_DOMAIN=canary.example.com DNS_ADDR=":5353"
	dnsDomain := strings.TrimSuffix(env("DNS_DOMAIN", ""), ".")
	dnsAddr := env("DNS_ADDR", "")

	st := newStore()
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := indexHTML.ReadFile("index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})

	// Create token (supports "url", "pixel", "qr", "dns")
	mux.HandleFunc("/api/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-API-Key") != apiKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var t Token
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(t.Type) == "" {
			http.Error(w, "missing type", http.StatusBadRequest)
			return
		}
		if t.ID == "" {
			t.ID = randID(10)
		}
		t.CreatedAt = time.Now().UTC()
		st.addToken(t)
		log.Printf("[TOKEN] created id=%s type=%s label=%q note=%q", t.ID, t.Type, t.Label, t.Note)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			ID string `json:"id"`
		}{ID: t.ID})
	})

	// Link beacon: /t/{id}
	mux.HandleFunc("/t/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/t/")
		addNoCache(w)
		if id != "" {
			if _, ok := st.getToken(id); ok {
				ev := Event{
					TokenID:   id,
					Kind:      "link",
					RemoteIP:  clientIP(r),
					UserAgent: r.UserAgent(),
					At:        time.Now().UTC(),
				}
				st.addEvent(ev)
				log.Printf("[EVENT] link  id=%s ip=%s ua=%q", ev.TokenID, ev.RemoteIP, ev.UserAgent)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Tracking pixel: /p/{id}.png
	mux.HandleFunc("/p/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/p/")
		id = strings.TrimSuffix(id, ".png")
		addNoCache(w)
		w.Header().Set("Content-Type", "image/png")
		if id != "" {
			if _, ok := st.getToken(id); ok {
				ev := Event{
					TokenID:   id,
					Kind:      "pixel",
					RemoteIP:  clientIP(r),
					UserAgent: r.UserAgent(),
					At:        time.Now().UTC(),
				}
				st.addEvent(ev)
				log.Printf("[EVENT] pixel id=%s ip=%s ua=%q", ev.TokenID, ev.RemoteIP, ev.UserAgent)
			}
		}
		img := image.NewRGBA(image.Rect(0, 0, 1, 1))
		img.Set(0, 0, color.RGBA{0, 0, 0, 0})
		_ = png.Encode(w, img)
	})

	// JSON events per token
	mux.HandleFunc("/api/events/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/events/")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(st.listEvents(id))
	})

	// Start DNS listener if configured
	if dnsDomain != "" && dnsAddr != "" {
		go runDNS(dnsAddr, dnsDomain, st)
		log.Printf("dns listener on %s for zone %s", dnsAddr, dnsDomain)
	}

	log.Printf("canary-server listening on %s (api key: %s)", addr, apiKey)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// =========================
// DNS authoritative listener
// =========================

func runDNS(addr, zone string, st *memoryStore) {
	h := dns.NewServeMux()
	h.HandleFunc(zone+".", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 {
			m := new(dns.Msg)
			m.SetReply(r)
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		labels := strings.Split(name, ".")
		zlabels := strings.Split(zone, ".")
		if len(labels) < len(zlabels) {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			_ = w.WriteMsg(m)
			return
		}
		// tokenid is the label immediately before the zone
		tokenID := labels[len(labels)-len(zlabels)-1]
		if _, ok := st.getToken(tokenID); ok {
			ip := remoteAddrIP(w.RemoteAddr())
			st.addEvent(Event{TokenID: tokenID, Kind: "dns", RemoteIP: ip, At: time.Now().UTC(), Name: name})
			log.Printf("[EVENT] dns   id=%s name=%s ip=%s", tokenID, name, ip)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		// Respond harmlessly; we don’t want to reveal infra
		switch q.Qtype {
		case dns.TypeA:
			rr, _ := dns.NewRR(name + ". 30 IN A 0.0.0.0")
			m.Answer = append(m.Answer, rr)
		case dns.TypeAAAA:
			rr, _ := dns.NewRR(name + ". 30 IN AAAA ::")
			m.Answer = append(m.Answer, rr)
		default:
			m.SetRcode(r, dns.RcodeNotImplemented)
		}
		_ = w.WriteMsg(m)
	})
	server := &dns.Server{Addr: addr, Net: "udp", Handler: h}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("dns udp error: %v", err)
		}
	}()
	serverTCP := &dns.Server{Addr: addr, Net: "tcp", Handler: h}
	go func() {
		if err := serverTCP.ListenAndServe(); err != nil {
			log.Printf("dns tcp error: %v", err)
		}
	}()
}

func remoteAddrIP(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

// =========================
/* Helpers */
// =========================

func randID(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func clientIP(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
		if v := r.Header.Get(h); v != "" {
			return strings.Split(v, ",")[0]
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func addNoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
