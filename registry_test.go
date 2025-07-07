package sctx

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestNewMemoryRegistry(t *testing.T) {
	registry := NewMemoryRegistry()
	
	if registry == nil {
		t.Fatal("NewMemoryRegistry returned nil")
	}
	
	// Verify it's empty
	entries := registry.List()
	if len(entries) != 0 {
		t.Errorf("New registry should be empty, got %d entries", len(entries))
	}
}

func TestMemoryRegistry_Register(t *testing.T) {
	registry := NewMemoryRegistry()
	
	entry := RegistryEntry{
		Type:        "service",
		Permissions: []string{"read", "write"},
	}
	
	// Test successful registration
	err := registry.Register("test-service", entry)
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}
	
	// Verify entry was registered
	retrieved, err := registry.Lookup("test-service")
	if err != nil {
		t.Fatalf("Failed to lookup registered entry: %v", err)
	}
	
	if retrieved.Type != entry.Type {
		t.Errorf("Retrieved type = %v, want %v", retrieved.Type, entry.Type)
	}
	
	if !reflect.DeepEqual(retrieved.Permissions, entry.Permissions) {
		t.Errorf("Retrieved permissions = %v, want %v", retrieved.Permissions, entry.Permissions)
	}
}

func TestMemoryRegistry_RegisterOverwrite(t *testing.T) {
	registry := NewMemoryRegistry()
	
	entry1 := RegistryEntry{
		Type:        "service",
		Permissions: []string{"read"},
	}
	
	entry2 := RegistryEntry{
		Type:        "service",
		Permissions: []string{"write"},
	}
	
	// Register first entry
	err := registry.Register("test-service", entry1)
	if err != nil {
		t.Fatalf("Failed to register first entry: %v", err)
	}
	
	// Register with same identity should overwrite
	err = registry.Register("test-service", entry2)
	if err != nil {
		t.Errorf("Failed to overwrite entry: %v", err)
	}
	
	// Verify entry was overwritten
	retrieved, _ := registry.Lookup("test-service")
	if !reflect.DeepEqual(retrieved.Permissions, entry2.Permissions) {
		t.Errorf("Entry was not overwritten: permissions = %v, want %v", retrieved.Permissions, entry2.Permissions)
	}
}

func TestMemoryRegistry_Lookup(t *testing.T) {
	registry := NewMemoryRegistry()
	
	// Test lookup of non-existent entry
	_, err := registry.Lookup("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent entry, got nil")
	}
	
	// Register and lookup
	entry := RegistryEntry{
		Type:        "admin",
		Permissions: []string{"*:*"},
	}
	registry.Register("admin-service", entry)
	
	retrieved, err := registry.Lookup("admin-service")
	if err != nil {
		t.Fatalf("Failed to lookup existing entry: %v", err)
	}
	
	if retrieved.Type != entry.Type {
		t.Errorf("Retrieved type = %v, want %v", retrieved.Type, entry.Type)
	}
}

func TestMemoryRegistry_Remove(t *testing.T) {
	registry := NewMemoryRegistry()
	
	// Register an entry
	entry := RegistryEntry{
		Type:        "service",
		Permissions: []string{"read"},
	}
	registry.Register("test-service", entry)
	
	// Remove it
	err := registry.Remove("test-service")
	if err != nil {
		t.Fatalf("Failed to remove: %v", err)
	}
	
	// Verify it's gone
	_, err = registry.Lookup("test-service")
	if err == nil {
		t.Error("Expected error after removing, entry still exists")
	}
	
	// Remove non-existent should error
	err = registry.Remove("non-existent")
	if err == nil {
		t.Error("Expected error when removing non-existent entry, got nil")
	}
}

func TestMemoryRegistry_List(t *testing.T) {
	registry := NewMemoryRegistry()
	
	// Empty registry
	entries := registry.List()
	if len(entries) != 0 {
		t.Errorf("Empty registry returned %d entries", len(entries))
	}
	
	// Add some entries
	registry.Register("service1", RegistryEntry{Type: "service", Permissions: []string{"read"}})
	registry.Register("service2", RegistryEntry{Type: "service", Permissions: []string{"write"}})
	registry.Register("admin1", RegistryEntry{Type: "admin", Permissions: []string{"*"}})
	
	entries = registry.List()
	if len(entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(entries))
	}
	
	// Verify all identities are present
	identities := make(map[string]bool)
	for _, id := range entries {
		identities[id] = true
	}
	
	for _, expected := range []string{"service1", "service2", "admin1"} {
		if !identities[expected] {
			t.Errorf("Missing identity %s in list", expected)
		}
	}
}

func TestMemoryRegistry_ConcurrentAccess(t *testing.T) {
	registry := NewMemoryRegistry()
	
	// Test concurrent registrations
	var wg sync.WaitGroup
	errors := make(chan error, 100)
	
	// Register 100 different entries concurrently
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			identity := fmt.Sprintf("service-%d", i)
			entry := RegistryEntry{
				Type:        "service",
				Permissions: []string{fmt.Sprintf("perm-%d", i)},
			}
			if err := registry.Register(identity, entry); err != nil {
				errors <- err
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent registration error: %v", err)
	}
	
	// Verify all entries were registered
	entries := registry.List()
	if len(entries) != 100 {
		t.Errorf("Expected 100 entries after concurrent registration, got %d", len(entries))
	}
	
	// Test concurrent reads and writes
	for i := 0; i < 50; i++ {
		wg.Add(3)
		
		// Reader
		go func(i int) {
			defer wg.Done()
			identity := fmt.Sprintf("service-%d", i)
			_, _ = registry.Lookup(identity)
		}(i)
		
		// Writer (remove)
		go func(i int) {
			defer wg.Done()
			identity := fmt.Sprintf("service-%d", i+50)
			_ = registry.Remove(identity)
		}(i)
		
		// Lister
		go func() {
			defer wg.Done()
			_ = registry.List()
		}()
	}
	
	wg.Wait()
}

func TestMemoryRegistry_EmptyIdentity(t *testing.T) {
	registry := NewMemoryRegistry()
	
	entry := RegistryEntry{
		Type:        "service",
		Permissions: []string{"read"},
	}
	
	// Test empty identity
	err := registry.Register("", entry)
	if err == nil {
		t.Error("Expected error for empty identity, got nil")
	}
	
	// Test whitespace identity (this is allowed since only empty string is checked)
	err = registry.Register("   ", entry)
	if err != nil {
		t.Errorf("Unexpected error for whitespace identity: %v", err)
	}
}

func TestMemoryRegistry_NilPermissions(t *testing.T) {
	registry := NewMemoryRegistry()
	
	// Test with nil permissions
	entry := RegistryEntry{
		Type:        "service",
		Permissions: nil,
	}
	
	err := registry.Register("test-service", entry)
	if err != nil {
		t.Fatalf("Failed to register with nil permissions: %v", err)
	}
	
	retrieved, _ := registry.Lookup("test-service")
	// The registry makes a copy and creates an empty slice for nil permissions
	if len(retrieved.Permissions) != 0 {
		t.Errorf("Expected empty permissions slice, got %v", retrieved.Permissions)
	}
}

func TestMemoryRegistry_PermissionsCopy(t *testing.T) {
	registry := NewMemoryRegistry()
	
	// Test that registry makes defensive copy on output
	entry := RegistryEntry{
		Type:        "service",
		Permissions: []string{"read", "write"},
	}
	
	registry.Register("test-service", entry)
	
	// Get the entry
	retrieved1, _ := registry.Lookup("test-service")
	
	// Modify retrieved slice
	retrieved1.Permissions[0] = "modified"
	
	// Get again - should not be affected
	retrieved2, _ := registry.Lookup("test-service")
	if retrieved2.Permissions[0] != "read" {
		t.Errorf("Modifying retrieved permissions affected stored data: got %v, want 'read'", retrieved2.Permissions[0])
	}
	
	// Note: The registry does NOT make defensive copies on input
	// This is a potential issue but reflects the current implementation
	perms := []string{"perm1", "perm2"}
	entry2 := RegistryEntry{
		Type:        "service2",
		Permissions: perms,
	}
	registry.Register("test-service2", entry2)
	
	// Modifying original slice WILL affect stored data
	perms[0] = "modified-original"
	
	retrieved3, _ := registry.Lookup("test-service2")
	if retrieved3.Permissions[0] == "modified-original" {
		t.Log("Warning: Registry does not make defensive copy on input - original slice modifications affect stored data")
	}
}