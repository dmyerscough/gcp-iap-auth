package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/imkira/gcp-iap-auth/jwt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	authRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gcp_iap_proxy_queries_total",
		Help: "The total number of queries",
	})
	authFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gcp_iap_proxy_auth_failures_total",
		Help: "The total number of authentication requests that failed",
	})
	authSuccess = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gcp_iap_proxy_auth_successful_total",
		Help: "The total number of authentication requests that were successful",
	})
)

type proxy struct {
	backend     *url.URL
	emailHeader string
	proxy       *httputil.ReverseProxy
}

func newProxy(backendURL, emailHeader string, timeout time.Duration) (*proxy, error) {
	backend, err := url.Parse(backendURL)
	if err != nil {
		return nil, fmt.Errorf("Could not parse URL '%s': %s", backendURL, err)
	}
	p := httputil.NewSingleHostReverseProxy(backend)
	p.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &proxy{
		backend:     backend,
		emailHeader: emailHeader,
		proxy:       p,
	}, nil
}

func (p *proxy) handler(res http.ResponseWriter, req *http.Request) {
	authRequests.Inc()

	claims, err := jwt.RequestClaims(req, cfg)
	if err != nil {
		if claims == nil || len(claims.Email) == 0 {
			log.Printf("Failed to authenticate (%v)\n", err)
		} else {
			log.Printf("Failed to authenticate %q (%v)\n", claims.Email, err)
		}
		authFailures.Inc()
		http.Error(res, "Unauthorized", http.StatusUnauthorized)
		return
	}
	authSuccess.Inc()
	if p.emailHeader != "" {
		req.Header.Set(p.emailHeader, claims.Email)
	}
	p.proxy.ServeHTTP(res, req)
}
