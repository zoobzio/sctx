#!/bin/bash

echo "Testing SCTX Demo Build..."

# Test default ECDSA mode
echo "1. Testing ECDSA P-256 mode (default)..."
./sctx-demo -h 2>&1 | grep -q "ed25519" && echo "✓ Help flag works" || echo "✗ Help flag failed"

# Test Ed25519 mode flag
echo -e "\n2. Testing Ed25519 mode flag..."
timeout 2s ./sctx-demo -ed25519 2>&1 | grep -q "High Performance" && echo "✓ Ed25519 mode detected" || echo "✗ Ed25519 mode not detected"

# Test default mode
echo -e "\n3. Testing default ECDSA mode..."
timeout 2s ./sctx-demo 2>&1 | grep -q "FIPS Compliant" && echo "✓ ECDSA mode detected" || echo "✗ ECDSA mode not detected"

echo -e "\nDemo build test complete!"