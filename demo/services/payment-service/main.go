package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	log.Println("=== Payment Service Starting ===")

	// Start the payment service
	mux := http.NewServeMux()
	mux.HandleFunc("/process", handlePayment)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Configure TLS
	cert, err := tls.LoadX509KeyPair("/app/certs/payment-service/cert.pem", "/app/certs/payment-service/key.pem")
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

	log.Println("Payment service listening on :8080")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func handlePayment(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	// In a real implementation, would verify the token
	token := r.Header.Get("X-Context-Token")
	if token == "" {
		http.Error(w, "Missing X-Context-Token", http.StatusUnauthorized)
		return
	}

	// TODO: Verify token has payments:process permission
	// For demo, we'll accept any token
	log.Printf("Processing payment with token: %.20s...", token)

	// Simulate payment processing
	time.Sleep(100 * time.Millisecond)

	response := "Payment processed successfully\n"
	response += fmt.Sprintf("Transaction ID: txn_%d\n", time.Now().Unix())
	response += "Amount: $45.49\n"
	response += "Status: Approved\n"

	log.Println("Payment processing completed")
	w.Write([]byte(response))
}