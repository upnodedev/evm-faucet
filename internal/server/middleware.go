package server

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v2"
	"github.com/kataras/hcaptcha"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/negroni"
)

type Limiter struct {
	mutex      sync.Mutex
	cache      *ttlcache.Cache
	proxyCount int
	ttl        time.Duration
}

func NewLimiter(proxyCount int, ttl time.Duration) *Limiter {
	cache := ttlcache.NewCache()
	cache.SkipTTLExtensionOnHit(true)
	return &Limiter{
		cache:      cache,
		proxyCount: proxyCount,
		ttl:        ttl,
	}
}

func (l *Limiter) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	address, err := readAddress(r)
	if err != nil {
		var mr *malformedRequest
		if errors.As(err, &mr) {
			renderJSON(w, claimResponse{Message: mr.message}, mr.status)
		} else {
			renderJSON(w, claimResponse{Message: http.StatusText(http.StatusInternalServerError)}, http.StatusInternalServerError)
		}
		return
	}

	if l.ttl <= 0 {
		next.ServeHTTP(w, r)
		return
	}

	clintIP := getClientIPFromRequest(l.proxyCount, r)
	l.mutex.Lock()

	if l.limitByKey(w, address) {
		l.mutex.Unlock()
		return
	}

	if l.checklimitByKey(w, clintIP).Seconds() > 0 {
		ttl := min(
			l.checklimitByKey(w, clintIP+"-0").Seconds(),
			l.checklimitByKey(w, clintIP+"-1").Seconds(),
			l.checklimitByKey(w, clintIP+"-2").Seconds(),
			l.checklimitByKey(w, clintIP+"-3").Seconds(),
		)

		if ttl > 0 {
			errMsg := fmt.Sprintf("You have exceeded the rate limit. Please wait %s before you try again", math.Round(ttl))
			renderJSON(w, claimResponse{Message: errMsg}, http.StatusTooManyRequests)

			l.mutex.Unlock()
			return
		}
	}

	l.cache.SetWithTTL(address, true, l.ttl)
	l.cache.SetWithTTL(clintIP, true, l.ttl)

	if l.checklimitByKey(w, clintIP+"-0").Seconds() <= 0 {
		l.cache.SetWithTTL(clintIP+"-0", true, l.ttl)
	} else if l.checklimitByKey(w, clintIP+"-1").Seconds() <= 0 {
		l.cache.SetWithTTL(clintIP+"-1", true, l.ttl)
	} else if l.checklimitByKey(w, clintIP+"-2").Seconds() <= 0 {
		l.cache.SetWithTTL(clintIP+"-2", true, l.ttl)
	} else if l.checklimitByKey(w, clintIP+"-3").Seconds() <= 0 {
		l.cache.SetWithTTL(clintIP+"-3", true, l.ttl)
	}

	l.mutex.Unlock()

	next.ServeHTTP(w, r)
	if w.(negroni.ResponseWriter).Status() != http.StatusOK {
		l.cache.Remove(address)
		l.cache.Remove(clintIP)
		return
	}
	log.WithFields(log.Fields{
		"address":  address,
		"clientIP": clintIP,
	}).Info("Maximum request limit has been reached")
}

func (l *Limiter) checklimitByKey(w http.ResponseWriter, key string) time.Duration {
	if _, ttl, err := l.cache.GetWithTTL(key); err == nil {
		return ttl
	}
	return 0
}

func (l *Limiter) limitByKey(w http.ResponseWriter, key string) bool {
	if _, ttl, err := l.cache.GetWithTTL(key); err == nil {
		errMsg := fmt.Sprintf("You have exceeded the rate limit. Please wait %s before you try again", ttl.Round(time.Second))
		renderJSON(w, claimResponse{Message: errMsg}, http.StatusTooManyRequests)
		return true
	}
	return false
}

func getClientIPFromRequest(proxyCount int, r *http.Request) string {
	if proxyCount > 0 {
		xForwardedFor := r.Header.Get("X-Forwarded-For")
		if xForwardedFor != "" {
			xForwardedForParts := strings.Split(xForwardedFor, ",")
			// Avoid reading the user's forged request header by configuring the count of reverse proxies
			partIndex := len(xForwardedForParts) - proxyCount
			if partIndex < 0 {
				partIndex = 0
			}
			return strings.TrimSpace(xForwardedForParts[partIndex])
		}
	}

	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}
	return remoteIP
}

type Captcha struct {
	client *hcaptcha.Client
	secret string
}

func NewCaptcha(hcaptchaSiteKey, hcaptchaSecret string) *Captcha {
	client := hcaptcha.New(hcaptchaSecret)
	client.SiteKey = hcaptchaSiteKey
	return &Captcha{
		client: client,
		secret: hcaptchaSecret,
	}
}

func (c *Captcha) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if c.secret == "" {
		next.ServeHTTP(w, r)
		return
	}

	response := c.client.VerifyToken(r.Header.Get("h-captcha-response"))
	if !response.Success {
		renderJSON(w, claimResponse{Message: "Captcha verification failed, please try again"}, http.StatusTooManyRequests)
		return
	}

	next.ServeHTTP(w, r)
}
