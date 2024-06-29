package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/dsa"
	"crypto/sha256"
	"crypto/hmac"
	"golang.org/x/crypto/argon2"

	"encoding/json"
	"errors"
	
	"github.com/google/uuid"
	"github.com/dgraph-io/badger/v3"
    
	
)

// _____ STRUCTS _____

type User struct {
	Username   string
	PrivateKey *rsa.PrivateKey
	DSSignKey  *dsa.PrivateKey
	RootKey    []byte
}

type UserKeys struct {
	PrivateKey *rsa.PrivateKey
	DSSignKey  *dsa.PrivateKey
}

type Salt struct {
	Username string
	Salt,
	HashedPassword []byte
}

type SecureData struct {
	EncContent,
	Tag []byte
}

// _____ CONSTANTS _____
const KEY_LENGTH = 256
const SALT_PURPOSE_STRING = "SALT_PURPOSE_STRING"
const DB_PATH = "/Users/rodrigo.ortiz/Github/SecureFileSharingSystem"

// _____ HELPER FUNCTIONS _____
func uuidFromBytes(key []byte, purpose string) (uuid.UUID, error) {
	hashedKey := deriveKey(key, purpose)
	return uuid.FromBytes(hashedKey[:16])
}

func uuidFromStrings(keyString, purpose string) (uuid.UUID, error) {
	key, err := json.Marshal(keyString)
	if err != nil {
		return uuid.Nil, err
	}
	hashedKey := sha256.Sum256(key)
	return uuidFromBytes(hashedKey[:], purpose)
}

func generateSalt() ([]byte, error) {
    salt := make([]byte, KEY_LENGTH)
    _, err := rand.Read(salt)
    if err != nil {
        return nil, err
    }
    return salt, nil
}

func hashPassword(password string, salt []byte) []byte {
    return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, KEY_LENGTH)
}

func verifyPassword(storedHashedPassword, salt []byte, password string) bool {
    hashedPassword := argon2.IDKey([]byte(password), salt, 1, 128*1024, 4, KEY_LENGTH)
    return subtle.ConstantTimeCompare(hashedPassword, storedHashedPassword) == 1
}

func deriveKey(key []byte, purpose string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(purpose))
	return h.Sum(nil)
}

func storeData(db *badger.DB, key string, value []byte) error {
	// Note: read-write transactions
	return db.Update(func(txn *badger.Txn) error {
		// Store the key-value pair
		return txn.Set([]byte(key), value)
	})
}

func getData(db *badger.DB, key string) ([]byte, error) {
	var value []byte
	// Note: read-only transactions
	err := db.View(func(txn *badger.Txn) error {
		// Retrieve the information stored in the database
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		// Read the value stored in the database
		return item.Value(func(val []byte) error {
			// Copy value for security purposes
			value = append([]byte{}, val...)
			return nil
		})
	})
	return value, err
}


// _____ MAIN FUNCTIONS _____

func InitUser(username string, password string) (userdataptr *User, err error) {
	salt, err := generateSalt()
	if (err != nil) {
		return nil, err
	}

	hashedPassword := hashPassword(password, salt)

	saltStruct := Salt{username, salt, hashedPassword}
	serializedSaltStruct, err := json.Marshal(&saltStruct)
	if (err != nil) {
		return nil, err
	}

	saltStructUUID, err := uuidFromStrings(username, SALT_PURPOSE_STRING)
	if (err != nil) {
		return nil, err
	}

	db, err := badger.Open(badger.DefaultOptions(DB_PATH))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	
	saltStructUUIDString := saltStructUUID.String()
	err = storeData(db, saltStructUUIDString, serializedSaltStruct)
	if err != nil {
		return nil, err
	}
	
	return nil, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	saltStructUUID, err := uuidFromStrings(username, SALT_PURPOSE_STRING)
	if err != nil {
		return nil, err
	}
	saltStructUUIDString := saltStructUUID.String()

	db, err := badger.Open(badger.DefaultOptions(DB_PATH))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	serializedSaltStruct, err := getData(db, saltStructUUIDString)
	if err != nil {
		return nil, err
	}

	var saltStruct Salt
	err = json.Unmarshal(serializedSaltStruct, &saltStruct)
	if err != nil {
		return nil, err
	}

	if !verifyPassword(saltStruct.HashedPassword, saltStruct.Salt, password) {
		return nil, errors.New("Invalid Credentials")
	}

	userStruct := User{username, nil, nil, nil}

	return &userStruct, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	return nil, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {

	return uuid.Nil, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
