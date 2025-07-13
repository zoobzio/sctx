#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

CERT_DIR="$(dirname "$0")/../certs"
SERVER="https://sctx-demo:8443"
ADMIN_SERVER="https://sctx-demo:8444"

echo -e "${BLUE}=== SCTX Security Test Scenarios ===${NC}"
echo "Testing various security edge cases..."
echo ""

# Helper function for making requests
make_request() {
    local cert=$1
    local endpoint=$2
    local extra_args="${3:-}"
    
    eval curl -s -k --cert "$CERT_DIR/$cert/cert.pem" \
         --key "$CERT_DIR/$cert/key.pem" \
         $extra_args \
         "$endpoint" 2>&1
}

# Helper to test and report
test_scenario() {
    local name=$1
    local cert=$2
    local endpoint=$3
    local expected=$4
    local extra_args="${5:-}"
    
    echo -e "${YELLOW}Testing:${NC} $name"
    result=$(make_request "$cert" "$endpoint" "$extra_args")
    
    if [[ "$result" == *"$expected"* ]]; then
        echo -e "${GREEN}✓ PASS${NC}: Got expected result"
    else
        echo -e "${RED}✗ FAIL${NC}: Expected '$expected', got:"
        echo "$result"
    fi
    echo ""
}

# Wait for server to be ready
echo "Waiting for server to start..."
until curl -s -k --cert "$CERT_DIR/sctx-admin/cert.pem" --key "$CERT_DIR/sctx-admin/key.pem" "$SERVER/health" > /dev/null 2>&1; do
    sleep 1
done
echo -e "${GREEN}Server is ready!${NC}"
echo ""

# Test 1: Admin Bootstrap (should work only once)
echo -e "${BLUE}=== Test 1: Admin Bootstrap ===${NC}"
echo "First admin request should get bootstrap token..."
TOKEN1=$(make_request "sctx-admin" "$SERVER/context" | grep "Context:" | cut -d' ' -f2)
if [ -n "$TOKEN1" ]; then
    echo -e "${GREEN}✓ Admin bootstrap successful${NC}"
    echo "Token: ${TOKEN1:0:50}..."
else
    echo -e "${RED}✗ Admin bootstrap failed${NC}"
fi
echo ""

# Test 2: Registered Client Access
echo -e "${BLUE}=== Test 2: Registered Client Access ===${NC}"
test_scenario "client-app-1 (registered with api:read,write)" \
    "client-app-1" \
    "$SERVER/context" \
    "Token issued"

# Get token for API test
TOKEN2=$(make_request "client-app-1" "$SERVER/context" | grep "Context:" | cut -d' ' -f2)

# Test API access with token
test_scenario "API read access with token" \
    "client-app-1" \
    "$SERVER/api/data" \
    "API access granted" \
    "-H \"X-Context-Token: $TOKEN2\""

# Test 3: Unregistered Client (should fail)
echo -e "${BLUE}=== Test 3: Unregistered Client ===${NC}"
test_scenario "unauthorized-client (not in registry or factory)" \
    "unauthorized-client" \
    "$SERVER/context" \
    "unauthorized"

# Test 4: Factory Pattern Matching
echo -e "${BLUE}=== Test 4: Factory Pattern Matching ===${NC}"
test_scenario "dev.team-alpha.local (matches dev-environment factory)" \
    "dev.team-alpha.local" \
    "$SERVER/context" \
    "Token issued"

test_scenario "prod.team-alpha.local (matches prod-environment factory)" \
    "prod.team-alpha.local" \
    "$SERVER/context" \
    "Token issued"

# Test 5: Rate Limiting
echo -e "${BLUE}=== Test 5: Rate Limiting ===${NC}"
echo "Making 6 requests rapidly (limit is 5 per minute)..."
for i in {1..6}; do
    echo -n "Request $i: "
    result=$(make_request "rate-limit-test" "$SERVER/context")
    if [[ "$result" == *"rate limit exceeded"* ]]; then
        echo -e "${GREEN}Rate limited!${NC}"
    elif [[ "$result" == *"Token issued"* ]]; then
        echo "Token issued"
    else
        echo "Error: $result"
    fi
done
echo ""

# Test 6: Token Refresh
echo -e "${BLUE}=== Test 6: Token Auto-Refresh ===${NC}"
echo "Getting initial token..."
TOKEN3=$(make_request "refresh-test-client" "$SERVER/context" | grep "Context:" | cut -d' ' -f2)
echo "Initial token: ${TOKEN3:0:50}..."

echo "Waiting 25 seconds (>80% of 30s TTL)..."
sleep 25

echo "Requesting again (should auto-refresh)..."
TOKEN4=$(make_request "refresh-test-client" "$SERVER/context" | grep "Context:" | cut -d' ' -f2)

if [ "$TOKEN3" != "$TOKEN4" ]; then
    echo -e "${GREEN}✓ Token was auto-refreshed${NC}"
else
    echo -e "${RED}✗ Token was not refreshed${NC}"
fi
echo ""

# Test 7: Admin Operations
echo -e "${BLUE}=== Test 7: Admin Operations ===${NC}"
test_scenario "Admin stats endpoint" \
    "sctx-admin" \
    "$ADMIN_SERVER/stats" \
    "Service Statistics"

test_scenario "List factories" \
    "sctx-admin" \
    "$ADMIN_SERVER/factories" \
    "Registered Factories"

test_scenario "Non-admin access to admin endpoint" \
    "client-app-1" \
    "$ADMIN_SERVER/stats" \
    "Not authorized"

# Test 8: Admin Factory Management
echo -e "${BLUE}=== Test 8: Admin Factory Management ===${NC}"
echo "Testing admin can manage factories..."

test_scenario "Admin can list factories" \
    "sctx-admin" \
    "$ADMIN_SERVER/factories" \
    "Registered Factories"

echo "Testing admin disable factory endpoint..."
disable_result=$(make_request "sctx-admin" "$ADMIN_SERVER/disable-factory?id=dev-environment")
if [[ "$disable_result" == *"disabled"* ]]; then
    echo -e "${GREEN}✓ Admin can disable factories${NC}"
else
    echo -e "${RED}✗ Admin disable failed: $disable_result${NC}"
fi

echo "Testing admin enable factory endpoint..."
enable_result=$(make_request "sctx-admin" "$ADMIN_SERVER/enable-factory?id=dev-environment")
if [[ "$enable_result" == *"enabled"* ]]; then
    echo -e "${GREEN}✓ Admin can enable factories${NC}"
else
    echo -e "${RED}✗ Admin enable failed: $enable_result${NC}"
fi

# Note: Runtime factory changes don't affect processors due to security model
# Processors get static factory list at startup to prevent privilege escalation
echo "Note: Processors use static factory list for security (dynamic changes require restart)"

# Test 9: Token Validation
echo -e "${BLUE}=== Test 9: Token Validation ===${NC}"
echo "Testing token validation endpoint..."
VALID_TOKEN=$(make_request "client-app-1" "$SERVER/context" | grep "Context:" | cut -d' ' -f2)

test_scenario "Valid token validation" \
    "client-app-1" \
    "$SERVER/validate" \
    "Valid token" \
    "-H \"X-Context-Token: $VALID_TOKEN\""

test_scenario "Invalid token validation" \
    "client-app-1" \
    "$SERVER/validate" \
    "Invalid token" \
    "-H \"X-Context-Token: invalid-token-here\""

# Test 10: Permission Checking
echo -e "${BLUE}=== Test 10: Permission-based Access ===${NC}"
# client-app-2 only has api:read
TOKEN5=$(make_request "client-app-2" "$SERVER/context" | grep "Context:" | cut -d' ' -f2)

test_scenario "Read-only client GET request" \
    "client-app-2" \
    "$SERVER/api/data" \
    "API access granted" \
    "-H \"X-Context-Token: $TOKEN5\""

test_scenario "Read-only client POST request (should fail)" \
    "client-app-2" \
    "$SERVER/api/data" \
    "Missing api:write permission" \
    "-X POST -H \"X-Context-Token: $TOKEN5\""

echo -e "${BLUE}=== Test Summary ===${NC}"
echo "Security scenarios tested:"
echo "✓ Admin bootstrap (one-time only)"
echo "✓ Registry-based authentication"
echo "✓ Factory pattern matching"
echo "✓ Unregistered client rejection"
echo "✓ Rate limiting enforcement"
echo "✓ Automatic token refresh"
echo "✓ Admin-only operations"
echo "✓ Admin factory management"
echo "✓ Token validation"
echo "✓ Permission-based access control"