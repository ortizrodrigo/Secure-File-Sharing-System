package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"crypto/aes"
	"crypto/rsa"
	"crypto/dsa"
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

// _____ FUNCTIONS _____

func InitUser(username string, password string) (userdataptr *User, err error) {
	
	
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

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	return uuid.Nil, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}