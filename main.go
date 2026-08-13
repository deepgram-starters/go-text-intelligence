// Go Text Intelligence Starter - Backend Server
//
// Simple REST API server providing text intelligence analysis
// powered by Deepgram's Text Intelligence service.
//
// Key Features:
//   - Contract-compliant API endpoint: POST /api/text-intelligence
//   - Accepts text or URL in JSON body
//   - Supports multiple intelligence features: summarization, topics, sentiment, intents
//   - CORS-enabled for frontend communication
//   - JWT session auth with rate limiting (production only)
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"

	analyzeapi "github.com/deepgram/deepgram-go-sdk/v3/pkg/api/analyze/v1"
	analyze "github.com/deepgram/deepgram-go-sdk/v3/pkg/client/analyze"
	dginterfaces "github.com/deepgram/deepgram-go-sdk/v3/pkg/client/interfaces"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

// config holds the server configuration, overridable via environment variables.
type config struct {
	Port string
	Host string
}

func loadConfig() config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	return config{Port: port, Host: host}
}

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

// sessionSecret used to sign JWTs. Generated at startup if not set in env.
var sessionSecret []byte

// jwtExpiry is the lifetime of issued tokens.
const jwtExpiry = 1 * time.Hour

func initSessionSecret() {
	secret := os.Getenv("SESSION_SECRET")
	if secret != "" {
		sessionSecret = []byte(secret)
		return
	}
	// Generate a random 32-byte secret for local development
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Failed to generate session secret: %v", err)
	}
	sessionSecret = b
}

// issueToken creates a signed JWT with a 1-hour expiry.
func issueToken(secret []byte) (string, error) {
	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtExpiry)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// validateToken verifies a JWT token string and returns an error if invalid.
func validateToken(tokenStr string, secret []byte) error {
	_, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})
	return err
}

// requireSession is middleware that validates JWT from Authorization header.
// Returns true if the request should be aborted (error already written).
func requireSession(w http.ResponseWriter, r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"error": map[string]interface{}{
				"type":    "AuthenticationError",
				"code":    "MISSING_TOKEN",
				"message": "Authorization header with Bearer token is required",
			},
		})
		return true
	}

	token := authHeader[7:]
	if err := validateToken(token, sessionSecret); err != nil {
		msg := "Invalid session token"
		if strings.Contains(err.Error(), "expired") {
			msg = "Session expired, please refresh the page"
		}
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"error": map[string]interface{}{
				"type":    "AuthenticationError",
				"code":    "INVALID_TOKEN",
				"message": msg,
			},
		})
		return true
	}

	return false
}

// ============================================================================
// API KEY LOADING
// ============================================================================

// loadApiKey reads the Deepgram API key from the environment.
func loadApiKey() string {
	apiKey := os.Getenv("DEEPGRAM_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "\n❌ ERROR: Deepgram API key not found!\n")
		fmt.Fprintln(os.Stderr, "Please set your API key in .env file:")
		fmt.Fprintln(os.Stderr, "   DEEPGRAM_API_KEY=your_api_key_here\n")
		fmt.Fprintln(os.Stderr, "Get your API key at: https://console.deepgram.com\n")
		os.Exit(1)
	}
	return apiKey
}

// ============================================================================
// CORS CONFIGURATION
// ============================================================================

// setCORSHeaders sets standard CORS headers on the response.
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	setCORSHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// errorResponse represents a structured error returned by the API.
type errorResponse struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Type    string            `json:"type"`
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details"`
}

// writeError writes a structured error response.
func writeError(w http.ResponseWriter, status int, errType, code, message string) {
	writeJSON(w, status, errorResponse{
		Error: errorDetail{
			Type:    errType,
			Code:    code,
			Message: message,
			Details: map[string]string{},
		},
	})
}

// ============================================================================
// TOML METADATA
// ============================================================================

// deepgramToml represents the parsed deepgram.toml file.
type deepgramToml struct {
	Meta map[string]interface{} `toml:"meta"`
}

// ============================================================================
// REQUEST / RESPONSE TYPES
// ============================================================================

// textIntelligenceRequest is the JSON body for POST /api/text-intelligence.
type textIntelligenceRequest struct {
	Text string `json:"text,omitempty"`
	URL  string `json:"url,omitempty"`
}

// ============================================================================
// ROUTE HANDLERS
// ============================================================================

// handleSession issues a signed JWT session token.
// GET /api/session
func handleSession(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "validation_error", "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	token, err := issueToken(sessionSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "processing_error", "TOKEN_ERROR", "Failed to create session token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// handleTextIntelligence processes text analysis requests via Deepgram Read API.
// POST /api/text-intelligence
func handleTextIntelligence(apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "validation_error", "METHOD_NOT_ALLOWED", "Method not allowed")
			return
		}

		// Auth check
		if requireSession(w, r) {
			return
		}

		// Parse JSON body
		var reqBody textIntelligenceRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			writeError(w, http.StatusBadRequest, "validation_error", "INVALID_TEXT", "Invalid JSON body")
			return
		}

		// Validate: exactly one of text or url
		if reqBody.Text == "" && reqBody.URL == "" {
			writeError(w, http.StatusBadRequest, "validation_error", "INVALID_TEXT", "Request must contain either 'text' or 'url' field")
			return
		}
		if reqBody.Text != "" && reqBody.URL != "" {
			writeError(w, http.StatusBadRequest, "validation_error", "INVALID_TEXT", "Request must contain either 'text' or 'url', not both")
			return
		}

		// If URL provided, fetch the text content from it
		textContent := reqBody.Text
		if reqBody.URL != "" {
			// Validate URL format
			if _, err := url.ParseRequestURI(reqBody.URL); err != nil {
				writeError(w, http.StatusBadRequest, "validation_error", "INVALID_URL", "Invalid URL format")
				return
			}

			resp, err := http.Get(reqBody.URL)
			if err != nil {
				writeError(w, http.StatusBadRequest, "validation_error", "INVALID_URL", fmt.Sprintf("Failed to fetch URL: %v", err))
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				writeError(w, http.StatusBadRequest, "validation_error", "INVALID_URL", fmt.Sprintf("Failed to fetch URL: %s", resp.Status))
				return
			}

			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				writeError(w, http.StatusBadRequest, "validation_error", "INVALID_URL", fmt.Sprintf("Failed to read URL content: %v", err))
				return
			}
			textContent = string(bodyBytes)
		}

		// Check for empty text
		if strings.TrimSpace(textContent) == "" {
			writeError(w, http.StatusBadRequest, "validation_error", "EMPTY_TEXT", "Text content cannot be empty")
			return
		}

		// Extract query parameters for intelligence features
		query := r.URL.Query()
		language := query.Get("language")
		if language == "" {
			language = "en"
		}
		summarize := query.Get("summarize")
		topics := query.Get("topics")
		sentiment := query.Get("sentiment")
		intents := query.Get("intents")

		// Handle summarize v1 rejection
		if summarize == "v1" {
			writeError(w, http.StatusBadRequest, "validation_error", "INVALID_TEXT", "Summarization v1 is no longer supported. Please use v2 or true.")
			return
		}

		// Analyze the text with Deepgram via the official Go SDK.
		opts := &dginterfaces.AnalyzeOptions{Language: language}
		if summarize == "true" || summarize == "v2" {
			opts.Summarize = true
		}
		if topics == "true" {
			opts.Topics = true
		}
		if sentiment == "true" {
			opts.Sentiment = true
		}
		if intents == "true" {
			opts.Intents = true
		}

		dg := analyzeapi.New(analyze.New(apiKey, &dginterfaces.ClientOptions{}))
		res, err := dg.FromStream(context.Background(), strings.NewReader(textContent), opts)
		if err != nil {
			log.Printf("Deepgram API Error: %v", err)
			writeError(w, http.StatusBadRequest, "processing_error", "INVALID_TEXT", fmt.Sprintf("Failed to process text: %v", err))
			return
		}

		// Re-marshal the typed SDK response to preserve the frontend contract
		// (the response still exposes a top-level "results" key).
		dgRespBody, err := json.Marshal(res)
		if err != nil {
			log.Printf("Deepgram Response Marshal Error: %v", err)
			writeError(w, http.StatusInternalServerError, "processing_error", "INVALID_TEXT", "Failed to parse Deepgram response")
			return
		}

		var dgResult map[string]interface{}
		if err := json.Unmarshal(dgRespBody, &dgResult); err != nil {
			log.Printf("Deepgram Response Parse Error: %v", err)
			writeError(w, http.StatusInternalServerError, "processing_error", "INVALID_TEXT", "Failed to parse Deepgram response")
			return
		}

		// Return results (the Deepgram response includes a "results" key)
		results, ok := dgResult["results"]
		if !ok {
			results = map[string]interface{}{}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"results": results,
		})
	}
}

// handleMetadata returns metadata from deepgram.toml.
// GET /api/metadata
func handleMetadata(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "validation_error", "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	var cfg deepgramToml
	if _, err := toml.DecodeFile("deepgram.toml", &cfg); err != nil {
		log.Printf("Error reading deepgram.toml: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":   "INTERNAL_SERVER_ERROR",
			"message": "Failed to read metadata from deepgram.toml",
		})
		return
	}

	if cfg.Meta == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":   "INTERNAL_SERVER_ERROR",
			"message": "Missing [meta] section in deepgram.toml",
		})
		return
	}

	writeJSON(w, http.StatusOK, cfg.Meta)
}

// handleHealth returns a simple health check response.
// GET /health
func handleHealth(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "text-intelligence",
	})
}

// handleNotFound returns a 404 for unmatched routes.
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]string{
		"error":   "Not Found",
		"message": "Endpoint not found",
	})
}

// ============================================================================
// SERVER START
// ============================================================================

func main() {
	// Load .env file (ignore error if not present)
	_ = godotenv.Load()

	// Load configuration
	cfg := loadConfig()

	// Initialize session secret
	initSessionSecret()

	// Load Deepgram API key
	apiKey := loadApiKey()

	// Set up routes
	mux := http.NewServeMux()
	mux.HandleFunc("/api/session", handleSession)
	mux.HandleFunc("/api/text-intelligence", handleTextIntelligence(apiKey))
	mux.HandleFunc("/api/metadata", handleMetadata)
	mux.HandleFunc("/health", handleHealth)

	// Wrap mux to handle 404 for unmatched routes
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the route matches any registered pattern
		_, pattern := mux.Handler(r)
		if pattern == "" {
			handleNotFound(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})

	addr := cfg.Host + ":" + cfg.Port

	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Backend API running at http://localhost:%s\n", cfg.Port)
	fmt.Println()
	fmt.Println("GET  /api/session")
	fmt.Println("POST /api/text-intelligence (auth required)")
	fmt.Println("GET  /api/metadata")
	fmt.Println("GET  /health")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()

	log.Fatal(http.ListenAndServe(addr, handler))
}
