package pwn_waf

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/valyala/fasthttp"
)

// PwnWaf adalah struktur data untuk middleware pwn-waf
type PwnWaf struct {
	IDS      *IDS
	Config   *Config
	whitelist map[string]bool
	mu       sync.RWMutex
}

// NewPwnWaf membuat instance baru dari middleware pwn-waf
func NewPwnWaf(config *Config) *PwnWaf {
	return &PwnWaf{
		IDS:      NewIDS(),
		Config:   config,
		whitelist: make(map[string]bool),
	}
}

// IDS adalah struktur data untuk IDS (Intrusion Detection System)
type IDS struct {
	rules []Rule
}

// NewIDS membuat instance baru dari IDS
func NewIDS() *IDS {
	return &IDS{
		rules: make([]Rule, 0),
	}
}

// Rule adalah struktur data untuk aturan IDS
type Rule struct {
	Pattern string
	Type    string
}

// Config adalah struktur data untuk konfigurasi pwn-waf
type Config struct {
	WhitelistIPs   []string
	WhitelistRefs  []string
	WhitelistAgents []string
	RulesFile      string
}

// ServeHTTP adalah fungsi middleware yang akan dipanggil untuk setiap request
func (p *PwnWaf) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Cek apakah request sudah di-whitelist
	if p.isWhitelisted(r) {
		http.HandlerFunc(p.next)(w, r)
		return
	}

	// Cek apakah request mengandung pola jahat
	if p.IDS.detect(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Jika tidak ada pola jahat, lanjutkan ke handler berikutnya
	http.HandlerFunc(p.next)(w, r)
}

// isWhitelisted cek apakah request sudah di-whitelist
func (p *PwnWaf) isWhitelisted(r *http.Request) bool {
	ip := r.RemoteAddr
	ref := r.Referer()
	agent := r.UserAgent()

	p.mu.RLock()
	defer p.mu.RUnlock()

	if _, ok := p.whitelist[ip]; ok {
		return true
	}

	if _, ok := p.whitelist[ref]; ok {
		return true
	}

	if _, ok := p.whitelist[agent]; ok {
		return true
	}

	return false
}

// detect cek apakah request mengandung pola jahat
func (p *IDS) detect(r *http.Request) bool {
	for _, rule := range p.rules {
		if strings.Contains(r.URL.Path, rule.Pattern) {
			return true
		}
	}

	return false
}

// LoadRules memuat aturan IDS dari file
func (p *IDS) LoadRules(file string) error {
	// Implementasi untuk memuat aturan IDS dari file
	return nil
}

// AddRule menambahkan aturan IDS baru
func (p *IDS) AddRule(rule Rule) {
	p.rules = append(p.rules, rule)
}

// AddWhitelist menambahkan IP, referer, atau agent ke whitelist
func (p *PwnWaf) AddWhitelist(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.whitelist[ip] = true
}

// AddWhitelistRef menambahkan referer ke whitelist
func (p *PwnWaf) AddWhitelistRef(ref string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.whitelist[ref] = true
}

// AddWhitelistAgent menambahkan agent ke whitelist
func (p *PwnWaf) AddWhitelistAgent(agent string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.whitelist[agent] = true
}