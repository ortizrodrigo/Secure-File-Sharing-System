package client

import (
	"os"
	"testing"

	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
)

const testDBPath = "/Users/rodrigo.ortiz/Github/SecureFileSharingSystem/client/test_db"
const testKBPath = "/Users/rodrigo.ortiz/Github/SecureFileSharingSystem/client/test_kb"

// Helper function to setup a test database
func setupTestDB(t *testing.T) *badger.DB {
	opts := badger.DefaultOptions(testDBPath).WithInMemory(true)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	return db
}

// Helper function to setup a test keybase
func setupTestKB(t *testing.T) *badger.DB {
	opts := badger.DefaultOptions(testKBPath).WithInMemory(true)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("failed to open test keybase: %v", err)
	}
	return db
}

// Helper function to cleanup test database and keybase
func cleanup(db *badger.DB) {
	db.Close()
	os.RemoveAll(testDBPath)
	os.RemoveAll(testKBPath)
}

func TestInitUser(t *testing.T) {
	db := setupTestDB(t)
	defer cleanup(db)
	kb := setupTestKB(t)
	defer cleanup(kb)

	// Test Case: Successful user initialization
	username := "testUser"
	password := "testPassword"

	user, err := InitUser(username, password)
	assert.NoError(t, err, "InitUser should not return an error")
	assert.Equal(t, username, user.Username, "Username should match the input")
	assert.NotNil(t, user.PrivateKey, "PrivateKey should not be nil")
	assert.NotNil(t, user.DSSignKey, "DSSignKey should not be nil")
	assert.NotNil(t, user.RootKey, "RootKey should not be nil")

	// Test Case: User initialization with empty password
	_, err = InitUser(username, "")
	assert.Error(t, err, "InitUser should return an error for empty password")

	// Additional test cases as needed...
}

func TestGetUser(t *testing.T) {
	db := setupTestDB(t)
	defer cleanup(db)
	kb := setupTestKB(t)
	defer cleanup(kb)

	// Initialize a user to be retrieved later
	username := "testUser"
	password := "testPassword"
	_, err := InitUser(username, password)
	assert.NoError(t, err, "InitUser should not return an error")

	// Test Case: Successful user retrieval
	user, err := GetUser(username, password)
	assert.NoError(t, err, "GetUser should not return an error")
	assert.Equal(t, username, user.Username, "Username should match the input")
	assert.NotNil(t, user.PrivateKey, "PrivateKey should not be nil")
	assert.NotNil(t, user.DSSignKey, "DSSignKey should not be nil")
	assert.NotNil(t, user.RootKey, "RootKey should not be nil")

	// Test Case: Incorrect password
	_, err = GetUser(username, "wrongPassword")
	assert.Error(t, err, "GetUser should return an error for incorrect password")

	// Test Case: Non-existent user
	_, err = GetUser("nonExistentUser", "password")
	assert.Error(t, err, "GetUser should return an error for non-existent user")

	// Additional test cases as needed...
}

