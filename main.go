package main

import (
	"fmt"
	"net/http"

	"github.com/pwn-waf/pwn_waf"
)

func main() {
	config := &pwn_waf.Config{
		WhitelistIPs:   []string{"192.168.1.1", "192.168.1.2"},
		WhitelistRefs:  []string{"https://example.com"},
		WhitelistAgents: []string{"Mozilla/5.0"},
		RulesFile:      "rules.txt",
	}

	pwnWaf := pwn_waf.NewPwnWaf(config)

	http.HandleFunc("/", pwnWaf.ServeHTTP)

	fmt.Println("Server started on port 8080")
	http.ListenAndServe(":8080", nil)
}