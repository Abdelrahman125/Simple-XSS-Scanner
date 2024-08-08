package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var payloads = []string{
	"<script>alert('XSS')</script>",
	"<img src=x onerror=alert('XSS')>",
	//payloads goes here
}

func scanURL(targetURL string) {
	client := &http.Client{Timeout: 10 * time.Second}

	for _, payload := range payloads {
		parsedURL, err := url.Parse(targetURL)
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			return
		}
		q := parsedURL.Query()
		//change q with actuall parameter, usually you don't need to change it
		q.Set("q", payload)
		parsedURL.RawQuery = q.Encode()
		resp, err := client.Get(parsedURL.String())
		if err != nil {
			fmt.Println("Error sending request:", err)
			continue
		}
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			continue
		}
		bodyString := string(bodyBytes)

		if strings.Contains(bodyString, payload) {
			fmt.Println("Potential XSS vulnerability found at:", parsedURL.String())
		}
	}
}

func main() {
	// Target URL to scan
	targetURL := "https://xss-game.appspot.com/level1/frame"
	scanURL(targetURL)
}
