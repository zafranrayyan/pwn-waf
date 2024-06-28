# pwn-waf: Middleware Keamanan untuk Aplikasi Web Go
pwn-waf adalah middleware keamanan untuk aplikasi web Go yang membantu melindungi dari ancaman OWASP Top 10, kerentanan yang diketahui, aktor jahat, botnet, crawler yang tidak diinginkan, dan serangan brute force. Middleware ini dapat diintegrasikan dengan mudah ke dalam aplikasi web Go dan menyediakan antarmuka yang mudah digunakan untuk mengkonfigurasi dan mengustomisasi fitur keamanan.

### Fitur
 * Mendeteksi pola jahat menggunakan IDS (Intrusion Detection System)
 * Melindungi dari serangan XSS, SQL injection, dan lain-lain
 * Mendeteksi dan memblokir IP, referer, dan agent yang tidak diinginkan
 * Mendukung whitelist IP, referer, dan agent
 * Dapat diintegrasikan dengan mudah ke dalam aplikasi web Go
 * Konfigurasi yang mudah dan fleksibel
 * Dapat diupgrade dan dikustomisasi dengan mudah

### Teknologi yang Digunakan
 * `Go` (Golang) sebagai bahasa pemrograman
 * `net/http` sebagai library untuk menghandle request dan response HTTP
 * `fasthttp` sebagai library untuk menghandle request dan response HTTP dengan performa tinggi
 * `sync` untuk menghandle concurrency dan synchronization

### Langkah-Langkah Menginstall/Menggunakan pwn-waf
1. Installasi
Untuk menginstall pwn-waf, Anda dapat menggunakan perintah berikut:
```
go get github.com/pwn-waf/pwn-waf
```
2. Konfigurasi
Buat file konfigurasi `config.json` dengan isi seperti berikut:
```
{
  "WhitelistIPs": ["192.168.1.1", "192.168.1.2"],
  "WhitelistRefs": ["https://example.com"],
  "WhitelistAgents": ["Mozilla/5.0"],
  "RulesFile": "rules.txt"
}
```
3. Menggunakan pwn-waf
Import pwn-waf ke dalam aplikasi web Go Anda dan buat instance baru dari middleware pwn-waf:
```go
import (
  "github.com/pwn-waf/pwn-waf"
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
```
### 4. Menggunakan IDS
Buat file `rules.txt` dengan isi seperti berikut:
```
# Aturan IDS untuk mendeteksi pola jahat
Rule 1: /admin/login.php
Rule 2: UNION SELECT
Rule 3: <script>
Rule 4: botnet_ip_1
Rule 5: bad_crawler_1
```
IDS akan memuat aturan dari file `rules.txt` dan mendeteksi pola jahat dalam request.


### Kontribusi
Jika Anda ingin berkontribusi pada pwn-waf, silakan buat pull request ke repository GitHub ini. Kami sangat menghargai kontribusi Anda!

