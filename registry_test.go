package sctx

import (
	"fmt"
	"sort"
	"sync"
	"testing"
)

func TestNewMemoryRegistry(t *testing.T) {
	registry := NewMemoryRegistry()
	if registry == nil {
		t.Fatal("NewMemoryRegistry returned nil")
	}

	// Verify it implements Registry interface
	var _ Registry = registry

	// Should be empty initially
	identities := registry.List()
	if len(identities) != 0 {
		t.Errorf("Expected 0 identities in new registry, got %d", len(identities))
	}
}

func TestMemoryRegistry_Register(t *testing.T) {
	registry := NewMemoryRegistry()

	tests := []struct {
		name        string
		identity    string
		entry       RegistryEntry
		wantErr     bool
		expectedErr string
	}{
		{
			name:     "valid registration",
			identity: "test-service",
			entry: RegistryEntry{
				Type:        "service",
				Permissions: []string{"read", "write"},
			},
			wantErr: false,
		},
		{
			name:     "empty permissions",
			identity: "minimal-service",
			entry: RegistryEntry{
				Type:        "service",
				Permissions: []string{},
			},
			wantErr: false,
		},
		{
			name:     "nil permissions",
			identity: "nil-perms-service",
			entry: RegistryEntry{
				Type:        "service",
				Permissions: nil,
			},
			wantErr: false,
		},
		{
			name:        "empty identity",
			identity:    "",
			entry:       RegistryEntry{Type: "service", Permissions: []string{"read"}},
			wantErr:     true,
			expectedErr: "identity cannot be empty",
		},
		{
			name:     "special characters in identity",
			identity: "service-with-special-chars-éñ-🔐",
			entry: RegistryEntry{
				Type:        "worker",
				Permissions: []string{"special:permission"},
			},
			wantErr: false,
		},
		{
			name:     "very long identity",
			identity: fmt.Sprintf("very-long-identity-%s", string(make([]byte, 1000))),
			entry: RegistryEntry{
				Type:        "service",
				Permissions: []string{"long:permission"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.Register(tt.identity, tt.entry)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				// Verify registration by looking it up
				retrieved, lookupErr := registry.Lookup(tt.identity)
				if lookupErr != nil {
					t.Errorf("Failed to lookup registered identity: %v", lookupErr)
				}

				if retrieved.Type != tt.entry.Type {
					t.Errorf("Expected type %s, got %s", tt.entry.Type, retrieved.Type)
				}

				if len(retrieved.Permissions) != len(tt.entry.Permissions) {
					t.Errorf("Expected %d permissions, got %d", len(tt.entry.Permissions), len(retrieved.Permissions))
				}

				for i, perm := range tt.entry.Permissions {
					if i >= len(retrieved.Permissions) || retrieved.Permissions[i] != perm {
						t.Errorf("Permission mismatch at index %d: expected %s, got %s", i, perm, retrieved.Permissions[i])
					}
				}
			}
		})
	}
}

func TestMemoryRegistry_RegisterUpdate(t *testing.T) {
	registry := NewMemoryRegistry()
	identity := "updateable-service"

	// Initial registration
	initialEntry := RegistryEntry{
		Type:        "service",
		Permissions: []string{"read"},
	}

	err := registry.Register(identity, initialEntry)
	if err != nil {
		t.Fatalf("Initial registration failed: %v", err)
	}

	// Verify initial state
	retrieved, err := registry.Lookup(identity)
	if err != nil {
		t.Fatalf("Initial lookup failed: %v", err)
	}

	if len(retrieved.Permissions) != 1 || retrieved.Permissions[0] != "read" {
		t.Error("Initial registration not correct")
	}

	// Update registration
	updatedEntry := RegistryEntry{
		Type:        "admin",
		Permissions: []string{"read", "write", "admin"},
	}

	err = registry.Register(identity, updatedEntry)
	if err != nil {
		t.Fatalf("Update registration failed: %v", err)
	}

	// Verify updated state
	retrieved, err = registry.Lookup(identity)
	if err != nil {
		t.Fatalf("Updated lookup failed: %v", err)
	}

	if retrieved.Type != "admin" {
		t.Errorf("Expected type 'admin', got %s", retrieved.Type)
	}

	if len(retrieved.Permissions) != 3 {
		t.Errorf("Expected 3 permissions after update, got %d", len(retrieved.Permissions))
	}

	expectedPerms := []string{"read", "write", "admin"}
	for i, expected := range expectedPerms {
		if i >= len(retrieved.Permissions) || retrieved.Permissions[i] != expected {
			t.Errorf("Updated permission mismatch at index %d: expected %s, got %s", i, expected, retrieved.Permissions[i])
		}
	}
}

func TestMemoryRegistry_Lookup(t *testing.T) {
	registry := NewMemoryRegistry()

	// Register test entries
	entries := map[string]RegistryEntry{
		"service1": {Type: "service", Permissions: []string{"read"}},
		"service2": {Type: "worker", Permissions: []string{"read", "write"}},
		"admin":    {Type: "admin", Permissions: []string{"admin:all"}},
	}

	for identity, entry := range entries {
		registry.Register(identity, entry)
	}

	// Test successful lookups
	for identity, expected := range entries {
		t.Run(fmt.Sprintf("lookup %s", identity), func(t *testing.T) {
			retrieved, err := registry.Lookup(identity)
			if err != nil {
				t.Fatalf("Lookup failed: %v", err)
			}

			if retrieved.Type != expected.Type {
				t.Errorf("Expected type %s, got %s", expected.Type, retrieved.Type)
			}

			if len(retrieved.Permissions) != len(expected.Permissions) {
				t.Errorf("Expected %d permissions, got %d", len(expected.Permissions), len(retrieved.Permissions))
			}
		})
	}

	// Test failed lookup
	t.Run("lookup non-existent", func(t *testing.T) {
		_, err := registry.Lookup("non-existent")
		if err == nil {
			t.Error("Expected error for non-existent identity")
		}

		expectedErr := "identity not found in registry"
		if err.Error() != expectedErr {
			t.Errorf("Expected error %q, got %q", expectedErr, err.Error())
		}
	})

	// Test that returned entry is a copy (external modification doesn't affect registry)
	t.Run("returned entry is copy", func(t *testing.T) {
		retrieved, err := registry.Lookup("service2")
		if err != nil {
			t.Fatalf("Lookup failed: %v", err)
		}

		// Modify the returned permissions
		originalLen := len(retrieved.Permissions)
		retrieved.Permissions = append(retrieved.Permissions, "malicious:permission")
		retrieved.Type = "hacked"

		// Lookup again and verify original data is unchanged
		retrieved2, err := registry.Lookup("service2")
		if err != nil {
			t.Fatalf("Second lookup failed: %v", err)
		}

		if len(retrieved2.Permissions) != originalLen {
			t.Error("External modification affected registry data")
		}

		if retrieved2.Type != "worker" {
			t.Error("External modification affected registry type")
		}
	})
}

func TestMemoryRegistry_Remove(t *testing.T) {
	registry := NewMemoryRegistry()

	// Register some entries
	entries := []string{"service1", "service2", "admin"}
	for _, identity := range entries {
		entry := RegistryEntry{
			Type:        "service",
			Permissions: []string{"read"},
		}
		registry.Register(identity, entry)
	}

	// Verify all are registered
	if len(registry.List()) != len(entries) {
		t.Errorf("Expected %d entries, got %d", len(entries), len(registry.List()))
	}

	// Test successful removal
	err := registry.Remove("service1")
	if err != nil {
		t.Errorf("Remove failed: %v", err)
	}

	// Verify it's gone
	_, err = registry.Lookup("service1")
	if err == nil {
		t.Error("Removed identity should not be found")
	}

	// Verify others still exist
	_, err = registry.Lookup("service2")
	if err != nil {
		t.Error("Other identities should still exist")
	}

	// Test removing non-existent identity
	err = registry.Remove("non-existent")
	if err == nil {
		t.Error("Expected error when removing non-existent identity")
	}

	expectedErr := "identity not found in registry"
	if err.Error() != expectedErr {
		t.Errorf("Expected error %q, got %q", expectedErr, err.Error())
	}

	// Test removing already removed identity
	err = registry.Remove("service1")
	if err == nil {
		t.Error("Expected error when removing already removed identity")
	}
}

func TestMemoryRegistry_List(t *testing.T) {
	registry := NewMemoryRegistry()

	// Empty registry
	identities := registry.List()
	if len(identities) != 0 {
		t.Errorf("Expected 0 identities in empty registry, got %d", len(identities))
	}

	// Add identities
	expectedIdentities := []string{
		"service1",
		"service2", 
		"admin",
		"worker",
		"special-chars-éñ",
	}

	for _, identity := range expectedIdentities {
		entry := RegistryEntry{
			Type:        "service",
			Permissions: []string{"read"},
		}
		registry.Register(identity, entry)
	}

	// Get list
	identities = registry.List()
	if len(identities) != len(expectedIdentities) {
		t.Errorf("Expected %d identities, got %d", len(expectedIdentities), len(identities))
	}

	// Sort both slices for comparison (order is not guaranteed)
	sort.Strings(identities)
	sort.Strings(expectedIdentities)

	for i, expected := range expectedIdentities {
		if i >= len(identities) || identities[i] != expected {
			t.Errorf("Identity mismatch at index %d: expected %s, got %s", i, expected, identities[i])
		}
	}

	// Verify returned list is a copy (external modification doesn't affect registry)
	identities[0] = "modified"
	identities2 := registry.List()
	sort.Strings(identities2)
	
	if identities2[0] == "modified" {
		t.Error("External modification affected registry list")
	}

	// Remove some and verify list updates
	registry.Remove("service1")
	registry.Remove("admin")

	identities = registry.List()
	if len(identities) != len(expectedIdentities)-2 {
		t.Errorf("Expected %d identities after removal, got %d", len(expectedIdentities)-2, len(identities))
	}

	// Should not contain removed identities
	for _, identity := range identities {
		if identity == "service1" || identity == "admin" {
			t.Errorf("Removed identity %s should not be in list", identity)
		}
	}
}

func TestMemoryRegistry_ConcurrentAccess(t *testing.T) {
	registry := NewMemoryRegistry()

	var wg sync.WaitGroup
	errors := make(chan error, 200)

	// Number of concurrent operations
	numGoroutines := 10
	numOperationsPerGoroutine := 20

	// Concurrent registrations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOperationsPerGoroutine; j++ {
				identity := fmt.Sprintf("concurrent-register-%d-%d", id, j)
				entry := RegistryEntry{
					Type:        "service",
					Permissions: []string{fmt.Sprintf("perm-%d-%d", id, j)},
				}

				err := registry.Register(identity, entry)
				if err != nil {
					errors <- err
					return
				}
			}
		}(i)
	}

	// Concurrent lookups
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOperationsPerGoroutine; j++ {
				identity := fmt.Sprintf("concurrent-register-%d-%d", id, j)

				// Try to lookup (may or may not exist depending on timing)
				entry, err := registry.Lookup(identity)
				if err == nil && entry == nil {
					errors <- fmt.Errorf("got nil entry for existing identity %s", identity)
					return
				}
				// It's ok if lookup fails - the identity might not be registered yet
			}
		}(i)
	}

	// Concurrent removals
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOperationsPerGoroutine/2; j++ {
				identity := fmt.Sprintf("concurrent-register-%d-%d", id, j)

				// Try to remove (may or may not exist)
				_ = registry.Remove(identity) // Error is ok if not found
			}
		}(i)
	}

	// Concurrent list operations
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for j := 0; j < numOperationsPerGoroutine; j++ {
				identities := registry.List()
				if len(identities) < 0 {
					errors <- fmt.Errorf("negative list length: %d", len(identities))
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}

	// Final state should be consistent
	finalList := registry.List()
	if len(finalList) < 0 {
		t.Errorf("Final list length is negative: %d", len(finalList))
	}

	// All listed identities should be retrievable
	for _, identity := range finalList {
		_, err := registry.Lookup(identity)
		if err != nil {
			t.Errorf("Listed identity %s is not retrievable: %v", identity, err)
		}
	}
}

func TestMemoryRegistry_Interface(t *testing.T) {
	// Verify that MemoryRegistry implements Registry interface
	var registry Registry = NewMemoryRegistry()

	identity := "interface-test"
	entry := RegistryEntry{
		Type:        "service",
		Permissions: []string{"read", "write"},
	}

	// Test all interface methods
	err := registry.Register(identity, entry)
	if err != nil {
		t.Errorf("Interface Register failed: %v", err)
	}

	retrieved, err := registry.Lookup(identity)
	if err != nil {
		t.Errorf("Interface Lookup failed: %v", err)
	}
	if retrieved == nil {
		t.Error("Interface Lookup returned nil entry")
	}

	identities := registry.List()
	if len(identities) == 0 {
		t.Error("Interface List returned empty list")
	}

	err = registry.Remove(identity)
	if err != nil {
		t.Errorf("Interface Remove failed: %v", err)
	}
}

func TestMemoryRegistry_EdgeCases(t *testing.T) {
	registry := NewMemoryRegistry()

	t.Run("whitespace identity", func(t *testing.T) {
		entry := RegistryEntry{Type: "service", Permissions: []string{"read"}}

		// Register identity with just whitespace
		err := registry.Register("   ", entry)
		if err != nil {
			t.Errorf("Register with whitespace identity failed: %v", err)
		}

		// Should be retrievable
		_, err = registry.Lookup("   ")
		if err != nil {
			t.Error("Whitespace identity should be retrievable")
		}
	})

	t.Run("newline in identity", func(t *testing.T) {
		entry := RegistryEntry{Type: "service", Permissions: []string{"read"}}
		identity := "identity\nwith\nnewlines"

		err := registry.Register(identity, entry)
		if err != nil {
			t.Errorf("Register with newline identity failed: %v", err)
		}

		_, err = registry.Lookup(identity)
		if err != nil {
			t.Error("Newline identity should be retrievable")
		}
	})

	t.Run("very large permissions list", func(t *testing.T) {
		largePermissions := make([]string, 10000)
		for i := range largePermissions {
			largePermissions[i] = fmt.Sprintf("permission-%d", i)
		}

		entry := RegistryEntry{Type: "service", Permissions: largePermissions}
		identity := "large-permissions"

		err := registry.Register(identity, entry)
		if err != nil {
			t.Errorf("Register with large permissions failed: %v", err)
		}

		retrieved, err := registry.Lookup(identity)
		if err != nil {
			t.Errorf("Lookup with large permissions failed: %v", err)
		}

		if len(retrieved.Permissions) != len(largePermissions) {
			t.Errorf("Expected %d permissions, got %d", len(largePermissions), len(retrieved.Permissions))
		}
	})

	t.Run("duplicate permissions in entry", func(t *testing.T) {
		entry := RegistryEntry{
			Type:        "service",
			Permissions: []string{"read", "write", "read", "read", "write"}, // Duplicates
		}
		identity := "duplicate-perms"

		err := registry.Register(identity, entry)
		if err != nil {
			t.Errorf("Register with duplicate permissions failed: %v", err)
		}

		retrieved, err := registry.Lookup(identity)
		if err != nil {
			t.Errorf("Lookup with duplicate permissions failed: %v", err)
		}

		// Should preserve duplicates (registry doesn't deduplicate)
		if len(retrieved.Permissions) != 5 {
			t.Errorf("Expected 5 permissions (with duplicates), got %d", len(retrieved.Permissions))
		}
	})
}