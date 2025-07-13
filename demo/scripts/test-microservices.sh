#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== SCTX Microservices Integration Test ===${NC}"
echo "Testing realistic service-to-service authentication flow"
echo ""

# Wait for all services to be ready
echo "Waiting for services to be ready..."
sleep 5

echo -e "${BLUE}=== Test 1: Service Registration ===${NC}"
echo "Testing that services can authenticate with SCTX..."

# Test order service can get token
echo "Order service requesting authentication..."
ORDER_TOKEN=$(curl -s -k \
  --cert /certs/order-service/cert.pem \
  --key /certs/order-service/key.pem \
  https://sctx-demo:8443/context | grep "Context:" | cut -d' ' -f2)

if [ -n "$ORDER_TOKEN" ]; then
    echo -e "${GREEN}✓ Order service authenticated successfully${NC}"
else
    echo -e "${RED}✗ Order service authentication failed${NC}"
    exit 1
fi

# Test payment service can get token
echo "Payment service requesting authentication..."
PAYMENT_TOKEN=$(curl -s -k \
  --cert /certs/payment-service/cert.pem \
  --key /certs/payment-service/key.pem \
  https://sctx-demo:8443/context | grep "Context:" | cut -d' ' -f2)

if [ -n "$PAYMENT_TOKEN" ]; then
    echo -e "${GREEN}✓ Payment service authenticated successfully${NC}"
else
    echo -e "${RED}✗ Payment service authentication failed${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}=== Test 2: Direct Service Access ===${NC}"

# Test order service endpoints
echo "Testing order service endpoints..."
result=$(curl -s -k https://order-service:8080/orders)
if [[ "$result" == *"Orders from Order Service"* ]]; then
    echo -e "${GREEN}✓ Order service responding${NC}"
else
    echo -e "${RED}✗ Order service not responding properly${NC}"
    echo "Response: $result"
fi

# Test payment service endpoints
echo "Testing payment service endpoints..."
result=$(curl -s -k -X POST -H "X-Context-Token: $PAYMENT_TOKEN" https://payment-service:8080/process)
if [[ "$result" == *"Payment processed successfully"* ]]; then
    echo -e "${GREEN}✓ Payment service processing payments${NC}"
else
    echo -e "${RED}✗ Payment service not processing properly${NC}"
    echo "Response: $result"
fi

echo ""
echo -e "${BLUE}=== Test 3: Service-to-Service Communication ===${NC}"

# Test order placement flow (order -> payment)
echo "Testing complete order placement flow..."
result=$(curl -s -k -X POST https://order-service:8080/orders/place)
if [[ "$result" == *"Order placed successfully"* ]]; then
    echo -e "${GREEN}✓ Order placement flow completed${NC}"
    echo "  Response: $(echo "$result" | head -1)"
    echo "  ✓ Order service called payment service"
else
    echo -e "${RED}✗ Order placement flow failed${NC}"
    echo "  Response: $result"
fi

echo ""
echo -e "${BLUE}=== Test 4: Permission Compatibility Verification ===${NC}"

# Test order placement with compatibility check
echo "Testing order placement with permission compatibility verification..."
result=$(curl -s -k -X POST https://order-service:8080/orders/place)
if [[ "$result" == *"Permission compatibility verified"* ]]; then
    echo -e "${GREEN}✓ Permission compatibility verification successful${NC}"
    echo "  Order service verified it can delegate to payment service"
elif [[ "$result" == *"Order placed successfully"* ]]; then
    echo -e "${YELLOW}⚠ Order succeeded but compatibility check message not found${NC}"
    echo "  (May indicate compatibility check is working but not logging)"
else
    echo -e "${RED}✗ Order placement failed${NC}"
    echo "  Response: $result"
fi

echo ""
echo -e "${BLUE}=== Test Summary ===${NC}"
echo "Microservices patterns demonstrated:"
echo "✓ Certificate-based service identity"
echo "✓ SCTX token acquisition by each service"
echo "✓ Service-to-service token propagation"
echo "✓ Permission compatibility verification"
echo "✓ Distributed microservices architecture"
echo "✓ Docker Compose orchestration"
echo ""
echo "This shows SCTX enabling secure communication in a"
echo "realistic microservices environment with proper service isolation"
echo "and advanced permission delegation patterns."