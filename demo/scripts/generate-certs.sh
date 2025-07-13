#!/bin/bash
set -e

echo "=== SCTX Demo Certificate Generation ==="
echo "This script generates certificates for testing various security scenarios"
echo ""

cd "$(dirname "$0")/../certs"

# Check if minica is installed
if ! command -v minica &> /dev/null; then
    echo "Installing minica..."
    go install github.com/jsha/minica@latest
fi

# Clean up old certificates
echo "Cleaning up old certificates..."
rm -rf *.pem */

echo ""
echo "=== Generating CA and certificates ==="

# Generate server certificate for sctx service
echo "1. Generating server certificate (sctx-service.local)..."
minica --domains "sctx-service.local,localhost" --ip-addresses "127.0.0.1,::1"

# Generate admin certificate with specific CN
echo "2. Generating admin certificate (CN=sctx-admin)..."
minica --domains "sctx-admin"

# Generate legitimate client certificates
echo "3. Generating legitimate client certificates..."
minica --domains "client-app-1"
minica --domains "client-app-2"
minica --domains "service-mesh-gateway"

# Generate certificates for testing edge cases
echo ""
echo "=== Generating edge case certificates ==="

# Certificate with no CN (should fall back to SAN)
echo "4. Generating certificate with DNS SAN only..."
minica --domains "san-only-client.local"

# Certificate that will be used for factory matching
echo "5. Generating certificates for factory pattern matching..."
minica --domains "dev.team-alpha.local"
minica --domains "prod.team-alpha.local"
minica --domains "dev.team-beta.local"

# Certificate for testing rate limiting
echo "6. Generating certificate for rate limit testing..."
minica --domains "rate-limit-test"

# Certificate that won't match any factory or registry
echo "7. Generating unregistered certificate..."
minica --domains "unauthorized-client"

# Certificate for testing refresh behavior
echo "8. Generating certificate for refresh testing..."
minica --domains "refresh-test-client"

# Certificate with special characters (testing identity extraction)
echo "9. Generating certificate with special CN..."
minica --domains "test-client-123.example"

# Certificates for microservices demo
echo "10. Generating certificate for order-service..."
minica --domains "order-service"

echo "11. Generating certificate for payment-service..."
minica --domains "payment-service"

echo ""
echo "=== Certificate Summary ==="
echo "CA Certificate: $(pwd)/minica.pem"
echo "CA Private Key: $(pwd)/minica-key.pem"
echo ""
echo "Generated certificates:"
find . -name "cert.pem" -type f | while read cert; do
    dir=$(dirname "$cert")
    cn=$(openssl x509 -in "$cert" -noout -subject | sed -n 's/.*CN=\([^,]*\).*/\1/p')
    echo "  - $dir/ (CN=$cn)"
done

echo ""
echo "=== Security Test Scenarios ==="
echo "These certificates enable testing of:"
echo "1. Admin bootstrap with sctx-admin"
echo "2. Normal client authentication"
echo "3. Factory pattern matching (team-alpha, team-beta)"
echo "4. Unregistered client rejection"
echo "5. Rate limiting behavior"
echo "6. Token refresh at <20% TTL"
echo "7. Identity extraction edge cases"
echo "8. Service mesh integration patterns"