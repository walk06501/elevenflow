package main

import (
	"log"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"
)

// WithMiddlewares wraps an http.Handler with the full middleware stack:
// RequestID → Logger → Recovery → CORS → Auth
func WithMiddlewares(h http.Handler, secret string) http.Handler {
	return RequestIDMiddleware(
		LoggerMiddleware(
			RecoveryMiddleware(
				CORSMiddleware(
					AuthMiddleware(secret, h),
				),
			),
		),
	)
}

// AuthMiddleware checks X-Api-Secret header against the configured secret.
// If secret is empty, auth is disabled (development mode).
func AuthMiddleware(secret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check endpoint
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		if secret != "" {
			reqSecret := r.Header.Get("X-Api-Secret")
			if reqSecret == "" {
				auth := r.Header.Get("Authorization")
				if len(auth) > 7 && (auth[:7] == "Bearer " || auth[:7] == "bearer ") {
					reqSecret = auth[7:]
				}
			}
			if reqSecret != secret {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware adds CORS headers for cross-origin requests from the Docker VPS.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, X-Api-Secret, X-Request-Id")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LoggerMiddleware logs every request with method, path, duration, and status.
func LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("[%s] %s %s - %v - %d",
			r.Header.Get("X-Request-Id"), r.Method, r.URL.Path,
			time.Since(start), rw.status)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// RecoveryMiddleware catches panics in handlers and returns 500 instead of crashing.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v\n%s", err, debug.Stack())
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// RequestIDMiddleware generates or propagates a request ID for tracing.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = strconv.FormatInt(time.Now().UnixNano(), 10)
			r.Header.Set("X-Request-Id", reqID)
		}
		w.Header().Set("X-Request-Id", reqID)
		next.ServeHTTP(w, r)
	})
}
