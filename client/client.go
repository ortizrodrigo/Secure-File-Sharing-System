package client

import (
	"github.com/google/uuid"
	"encoding/json"
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
    "golang.org/x/crypto/argon2"
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

// _____ HELPER FUNCTIONS _____
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


	

	return nil, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	return nil, nil
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
