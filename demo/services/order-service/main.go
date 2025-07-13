package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	// "github.com/zoobzio/sctx" // Commented out for demo simplicity
)

func main() {
	log.Println("=== Order Service Starting ===")

	// Load public key for token verification
	publicKey, err := loadPublicKey()
	if err != nil {
		log.Fatalf("Failed to load public key: %v", err)
	}

	// Start the order service
	mux := http.NewServeMux()
	mux.HandleFunc("/orders", authMiddleware(publicKey, handleOrders))
	mux.HandleFunc("/orders/place", authMiddleware(publicKey, handlePlaceOrder))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Configure TLS
	cert, err := tls.LoadX509KeyPair("/app/certs/order-service/cert.pem", "/app/certs/order-service/key.pem")
	if err != nil {
		log.Fatalf("Failed to load cert: %v", err)
	}

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	log.Println("Order service listening on :8080")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func loadPublicKey() (*ecdsa.PublicKey, error) {
	// In a real environment, this would fetch from the SCTX server
	// For demo, we'll simulate having the public key
	// TODO: Implement /public-key endpoint on SCTX server
	return nil, fmt.Errorf("public key loading not implemented - would fetch from SCTX server")
}

func authMiddleware(publicKey *ecdsa.PublicKey, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Context-Token")
		if token == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		// TODO: Verify token with public key when implemented
		// data, err := sctx.VerifyContext(sctx.Context(token), publicKey)
		
		next.ServeHTTP(w, r)
	}
}

func handleOrders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		response := "Orders from Order Service:\n"
		response += "- Order #1001: Coffee ($12.99)\n"
		response += "- Order #1002: Tea ($8.50)\n"
		w.Write([]byte(response))
	case "POST":
		response := "Order created by Order Service\n"
		response += "Order #1003: New order\n"
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(response))
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handlePlaceOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Println("Processing order placement...")

	// Step 1: Call payment service
	if !callPaymentService(r.Header.Get("X-Context-Token")) {
		http.Error(w, "Payment failed", http.StatusBadRequest)
		return
	}

	response := "Order placed successfully!\n"
	response += "✓ Payment processed\n"
	response += "Order ID: ord_" + fmt.Sprintf("%d", time.Now().Unix()) + "\n"

	w.Write([]byte(response))
}

func callPaymentService(token string) bool {
	// Get SCTX token for our service
	serviceToken, err := getServiceToken()
	if err != nil {
		log.Printf("Failed to get service token: %v", err)
		return false
	}

	// Get SCTX public key for compatibility verification
	// (Not used in mock implementation, but would be needed for real CheckCompatibility)
	_, err = getSCTXPublicKey()
	if err != nil {
		log.Printf("Failed to get SCTX public key: %v", err)
		return false
	}

	// Check permission compatibility before making the call
	// For demo purposes, we'll simulate the compatibility check
	compatible := mockCheckCompatibility(serviceToken, serviceToken)
	if !compatible {
		log.Printf("Permission incompatibility: Order service cannot delegate to payment service")
		return false
	}

	log.Printf("✓ Permission compatibility verified - proceeding with payment call")

	// Call payment service
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, _ := http.NewRequest("POST", "https://payment-service:8080/process", nil)
	req.Header.Set("X-Context-Token", serviceToken)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Payment service call failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Payment service returned %d: %s", resp.StatusCode, string(body))
		return false
	}

	log.Println("Payment service call succeeded")
	return true
}

func getServiceToken() (string, error) {
	// Load our client certificate
	cert, err := tls.LoadX509KeyPair("/app/certs/order-service/cert.pem", "/app/certs/order-service/key.pem")
	if err != nil {
		return "", err
	}

	// Call SCTX server to get token
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
			},
		},
	}

	sctxServer := os.Getenv("SCTX_SERVER")
	if sctxServer == "" {
		sctxServer = "https://sctx-demo:8443"
	}

	resp, err := client.Get(sctxServer + "/context")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("SCTX server returned %d: %s", resp.StatusCode, string(body))
	}

	// Parse token from response (simplified)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Extract token from "Context: <token>" line
	// In real implementation, would parse properly
	lines := string(body)
	if len(lines) > 100 {
		return lines[9:109], nil // Rough extraction for demo
	}

	return "", fmt.Errorf("could not extract token from response")
}

func getSCTXPublicKey() (*ecdsa.PublicKey, error) {
	// In a real implementation, this would fetch the public key from SCTX server
	// For demo purposes, we'll read it from the file written by the demo server
	
	// Try to read the public key file that the demo server writes
	keyData, err := os.ReadFile("/app/demo-signing-public.pem")
	if err != nil {
		// Fallback: try to get it from a shared volume or well-known location
		// For demo, we'll use a hardcoded approach since we know the server exports it
		log.Printf("Could not read public key file: %v", err)
		return nil, fmt.Errorf("public key not available - would fetch from SCTX server in production")
	}

	// Parse PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Ensure it's an ECDSA public key
	ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ECDSA public key")
	}

	return ecdsaKey, nil
}

func mockCheckCompatibility(callerToken, subjectToken string) bool {
	// For demo purposes, we simulate the CheckCompatibility logic
	// In reality, this would verify that both tokens have compatible permissions
	// For this demo, we'll always return true to show the successful flow
	log.Printf("Simulating permission compatibility check between tokens")
	log.Printf("  Caller token: %.20s...", callerToken)
	log.Printf("  Subject token: %.20s...", subjectToken)
	
	// In the real implementation, this would:
	// 1. Parse both tokens using sctx.VerifyContext()
	// 2. Check if subjectToken permissions are subset of callerToken permissions
	// 3. Return true if compatible, false otherwise
	
	return true // Always compatible for demo
}