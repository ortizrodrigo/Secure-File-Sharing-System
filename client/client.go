package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/dsa"
	"crypto/sha256"
	"crypto/hmac"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"

	"golang.org/x/crypto/argon2"

	"encoding/json"
	"errors"
	"io"
	
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
	RootKey    []byte
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
const symKeyLength = 32 // bytes
const asymKeyLength = 2048 // bytes
const signKeyLength = dsa.L1024N160
const saltPurposeString = "saltPurposeString"
const pubKeyPurposeString = "pubKeyPurposeString"
const verKeyPurposeString = "verKeyPurposeString"
const userKeysSymKeyPurposeString = "userKeysSymKeyPurposeString"
const userKeysMacKeyPurposeString = "userKeysMacKeyPurposeString"
const dbPath = "/Users/rodrigo.ortiz/Github/SecureFileSharingSystem/client/dataBase"
const kbPath = "/Users/rodrigo.ortiz/Github/SecureFileSharingSystem/client/keyBase"

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

func genRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func genSalt() ([]byte, error) {
    return genRandomBytes(symKeyLength)
}

// Hashing
func hashPassword(password string, salt []byte) []byte {
    return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, symKeyLength)
}

func verifyPassword(storedHashedPassword, salt []byte, password string) bool {
    hashedPassword := argon2.IDKey([]byte(password), salt, 1, 128*1024, 4, symKeyLength)
    return subtle.ConstantTimeCompare(hashedPassword, storedHashedPassword) == 1
}

// Keys
func deriveKey(key []byte, purpose string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(purpose))
	return h.Sum(nil)
}

func genPrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, asymKeyLength)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func genSignKey() (*dsa.PrivateKey, error) {
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, signKeyLength); err != nil {
		return nil, err
	}

	signKey := new(dsa.PrivateKey)
	signKey.PublicKey.Parameters = params
	err := dsa.GenerateKey(signKey, rand.Reader)
	if  err != nil {
		return nil, err
	}
	return signKey, nil
}

// Encryption
func symEnc(key, plainText []byte) ([]byte, error) {
	// Deterministically drive Advanced Encryption Standard Cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Use a counter mode cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a nonce
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	// Encrypt the plainText
	cipherText := aesGCM.Seal(nonce, nonce, plainText, nil)
	return cipherText, nil
}

func symDec(key, cipherText []byte) ([]byte, error) {
	// Deterministically drive Advanced Encryption Standard Cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Use a counter mode cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Verify cipherText length for decryption
	nonceSize := aesGCM.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.New("Invalid cipherText length")
	}

	// Decrypt cipherText
	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func asymEnc(pubKey *rsa.PublicKey, plainText []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plainText, nil)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func asymDec(privKey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func serializeThenSymEnc(key []byte, data interface{}) ([]byte, error) {
	serData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	
	return symEnc(key, serData)
}

func symDecThenDeserialize(key, cipherText []byte, data interface{}) error {
	plainText, err := symDec(key, cipherText)
	if err != nil {
		return err
	}

	return json.Unmarshal(plainText, data)
}

func serializeThenAsymEnc(pubKey *rsa.PublicKey, data interface{}) ([]byte, error) {
	serData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	
	return asymEnc(pubKey, serData)
}

func asymDecThenDeserialize(privKey *rsa.PrivateKey, cipherText []byte, data interface{}) error {
	plainText, err := asymDec(privKey, cipherText)
	if err != nil {
		return err
	}

	return json.Unmarshal(plainText, data)
}

// Data
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

func dbStore(key string, value []byte) error {
	db, err := badger.Open(badger.DefaultOptions(dbPath))
	if err != nil {
		return err
	}
	defer db.Close()
	return storeData(db, key, value)
}

func dbGet(key string) ([]byte, error) {
	db, err := badger.Open(badger.DefaultOptions(dbPath))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return getData(db, key)
}

func kbStore(key string, pubKey interface{}) error {
	db, err := badger.Open(badger.DefaultOptions(kbPath))
	if err != nil {
		return err
	}
	defer db.Close()

	var serPubKey []byte
	switch k := pubKey.(type) {
	case *rsa.PublicKey:
		serPubKey, err = x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return err
		}
	case *dsa.PublicKey:
		serPubKey, err = x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid key type")
	}

	return storeData(db, key, serPubKey)
}

func kbGet(key string) (interface{}, error) {
	db, err := badger.Open(badger.DefaultOptions(kbPath))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	serPubKey, err := getData(db, key)
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(serPubKey)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

// _____ MAIN FUNCTIONS _____

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Generate new User's salt for password hasing purposes
	salt, err := genSalt()
	if err != nil {
		return nil, err
	}

	// Generate saltStruct to store user log in credentials
	hashedPassword := hashPassword(password, salt)
	saltStruct := Salt{username, salt, hashedPassword}

	// Deterministically derive user's uuid to store log in credentials
	saltStructUUID, err := uuidFromStrings(username, saltPurposeString)
	if err != nil {
		return nil, err
	}
	saltStructUUIDString := saltStructUUID.String()
	
	// Store user log in credentials
	serializedSaltStruct, err := json.Marshal(&saltStruct)
	if err != nil {
		return nil, err
	}
	err = dbStore(saltStructUUIDString, serializedSaltStruct)
	if err != nil {
		return nil, err
	}

	// Generate user private key for asymmetric encryption purposes
	privKey, err := genPrivateKey()
	if err != nil {
		return nil, err
	}

	// Deterministically derive user's uuid to store rsa public key
	pubKeyUUID, err := uuidFromStrings(username, pubKeyPurposeString)
	if err != nil {
		return nil, err
	}
	pubKeyUUIDString := pubKeyUUID.String()

	// Store rsa public key
	err = kbStore(pubKeyUUIDString, &privKey.PublicKey)
	if err != nil {
		return nil, err
	}
	
	// Generate user sign key for digital signatures
	signKey, err := genSignKey()
	if err != nil {
		return nil, err
	}

	// Deterministically derive user's uuid to store dsa public key
	verKeyUUID, err := uuidFromStrings(username, verKeyPurposeString)
	if err != nil {
		return nil, err
	}
	verKeyUUIDString := verKeyUUID.String()

	// Store dsa public key
	err = kbStore(verKeyUUIDString, &signKey.PublicKey)
	if err != nil {
		return nil, err
	}

	// Generate user's root key for personal encryption purposes
	rootKey, err := genRandomBytes(symKeyLength)
	if err != nil {
		return nil, err
	}

	userKeysStruct := UserKeys{privKey, signKey, rootKey}

	// Generate new salt to derive a secure key
	userKeysSalt, err := genSalt()
	if err != nil {
		return nil, err
	}
	userKeysHashedPassword := hashPassword(password, userKeysSalt)

	// Generaye symmetric and MAC keys used to securely store userKeys
	userKeysSymKey := deriveKey(userKeysHashedPassword, userKeysSymKeyPurposeString)
	userKeysMacKey := deriveKey(userKeysHashedPassword, userKeysMacKeyPurposeString)

	// Generate user data struct
	userdataptr = &User{username, privKey, signKey, rootKey}
	
	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Deterministically derive user's uuid to store log in credentials
	saltStructUUID, err := uuidFromStrings(username, saltPurposeString)
	if err != nil {
		return nil, err
	}
	saltStructUUIDString := saltStructUUID.String()

	// Retrieve user log in credentials
	serializedSaltStruct, err := dbGet(saltStructUUIDString)
	if err != nil {
		return nil, err
	}
	var saltStruct Salt
	err = json.Unmarshal(serializedSaltStruct, &saltStruct)
	if err != nil {
		return nil, err
	}

	// Verify user log in credentials
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
