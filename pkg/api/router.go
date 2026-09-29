package api

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// ResponseRecorder wraps http.ResponseWriter to capture status codes for logging.
type ResponseRecorder struct {
	http.ResponseWriter
	StatusCode int
}

func (r *ResponseRecorder) WriteHeader(code int) {
	r.StatusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// Router configures and returns the HTTP handler with registered routes and middlewares.
func NewRouter(handler *Handler) http.Handler {
	mux := http.NewServeMux()

	// Direct & Versioned Endpoints
	mux.HandleFunc("/health", handler.Health)
	mux.HandleFunc("/api/v1/health", handler.Health)

	// Objects Collection (Upload)
	mux.HandleFunc("/objects", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/objects" && r.URL.Path != "/objects/" {
			// Specific object path (/objects/{id})
			dispatchObjectRoutes(handler, w, r)
			return
		}
		if r.Method == http.MethodPost {
			handler.Upload(w, r)
		} else {
			http.Error(w, `{"error":"method not allowed","code":"METHOD_NOT_ALLOWED"}`, http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/v1/objects", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/objects" && r.URL.Path != "/api/v1/objects/" {
			dispatchObjectRoutes(handler, w, r)
			return
		}
		if r.Method == http.MethodPost {
			handler.Upload(w, r)
		} else {
			http.Error(w, `{"error":"method not allowed","code":"METHOD_NOT_ALLOWED"}`, http.StatusMethodNotAllowed)
		}
	})

	// Objects Sub-paths (/objects/* and /api/v1/objects/*)
	mux.HandleFunc("/objects/", func(w http.ResponseWriter, r *http.Request) {
		dispatchObjectRoutes(handler, w, r)
	})
	mux.HandleFunc("/api/v1/objects/", func(w http.ResponseWriter, r *http.Request) {
		dispatchObjectRoutes(handler, w, r)
	})

	// Chain Middlewares
	return recoveryMiddleware(corsMiddleware(loggerMiddleware(mux)))
}

// dispatchObjectRoutes routes GET, HEAD, DELETE requests for /objects/{id} and POST /objects/{id}/rewrap.
func dispatchObjectRoutes(handler *Handler, w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/rewrap") {
		if r.Method == http.MethodPost {
			handler.ReWrap(w, r)
		} else {
			http.Error(w, `{"error":"method not allowed","code":"METHOD_NOT_ALLOWED"}`, http.StatusMethodNotAllowed)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		handler.Download(w, r)
	case http.MethodHead:
		handler.Head(w, r)
	case http.MethodDelete:
		handler.Delete(w, r)
	default:
		http.Error(w, `{"error":"method not allowed","code":"METHOD_NOT_ALLOWED"}`, http.StatusMethodNotAllowed)
	}
}

// loggerMiddleware logs incoming HTTP requests and response status codes with latency.
func loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &ResponseRecorder{ResponseWriter: w, StatusCode: http.StatusOK}
		next.ServeHTTP(rec, r)
		duration := time.Since(start)
		log.Printf("[HTTP] %s %s | Status: %d | Latency: %v | Remote: %s",
			r.Method, r.URL.Path, rec.StatusCode, duration, r.RemoteAddr)
	})
}

// recoveryMiddleware catches panics and prevents the server process from crashing.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[PANIC RECOVERED] %v", rec)
				http.Error(w, `{"error":"internal server error","code":"PANIC_RECOVERED"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware sets standard CORS headers allowing API accessibility.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Object-ID")
		w.Header().Set("Access-Control-Expose-Headers", "X-VaultGate-Object-ID, X-VaultGate-KMS-Key-ID, X-VaultGate-Algorithm, X-VaultGate-Created-At")

		if strings.EqualFold(r.Method, http.MethodOptions) {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
