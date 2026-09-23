package recon

import (
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

// LiveHost represents a subdomain that has a live web server
type LiveHost struct {
	URL        string
	StatusCode int
}

// CheckLive takes a list of subdomains and checks if they are live websites
func CheckLive(subdomains []string) []LiveHost {
	var liveHosts []LiveHost
	var wg sync.WaitGroup
	var mu sync.Mutex

	// We ignore SSL errors because hackers often find dev sites with broken SSL
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   5 * time.Second, // Don't wait forever for slow sites
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	for _, sub := range subdomains {
		wg.Add(1)
		// This is Go's concurrency! It checks hundreds of sites at the exact same time
		go func(s string) {
			defer wg.Done()

			url := "https://" + s
			resp, err := client.Get(url)

			if err == nil {
				resp.Body.Close()
				mu.Lock()
				liveHosts = append(liveHosts, LiveHost{
					URL:        url,
					StatusCode: resp.StatusCode,
				})
				mu.Unlock()
				return
			}

			// If HTTPS fails, try HTTP
			url = "http://" + s
			resp, err = client.Get(url)
			if err == nil {
				resp.Body.Close()
				mu.Lock()
				liveHosts = append(liveHosts, LiveHost{
					URL:        url,
					StatusCode: resp.StatusCode,
				})
				mu.Unlock()
			}
		}(sub)
	}

	wg.Wait() // Wait for all checks to finish
	return liveHosts
}
