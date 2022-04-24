package key

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"

	"golang.org/x/crypto/blake2b"
)

const (
	VERIFICATION_KEY_HASH_SIZE = 28
)

// Key is the generic type for keys
type Key struct {
	KeyType     KeyType `json:"type"`
	Description string  `json:"description"`
	CborHex     string  `json:"cborHex"`
}

// KeyType indicates the type of Key
type KeyType string

const (
	PAYMENT_SIGNING_KEY      KeyType = "PaymentSigningKeyShelley_ed25519"
	PAYMENT_VERIFICATION_KEY KeyType = "PaymentVerificationKeyShelley_ed25519"
)

// ToJson converts key to JSON
func (key *Key) ToJson() []byte {
	k := &Key{
		KeyType:     key.KeyType,
		Description: key.Description,
		CborHex:     key.CborHex,
	}

	jsonKey, _ := json.Marshal(k)

	return jsonKey
}

// ToJson converts JSON to key
func FromJson(data []byte) Key {
	key := &Key{}
	json.Unmarshal(data, key)
	return *key
}

// GenerateKeys generates a signing/verification key pair.
func GenerateKeys() (SigningKey, VerificationKey) {
	public, private, _ := ed25519.GenerateKey(nil)

	verificationKey := &VerificationKey{
		Public: public,
	}

	signingKey := &SigningKey{
		Private: private,
	}

	return *signingKey, *verificationKey
}

// SigningKey is a the type of key used for signing data. This key should always be kept private.
type SigningKey struct {
	Key
	Private ed25519.PrivateKey
}

// Sign signs the message with signingKey and returns a signature.
func (signingKey *SigningKey) Sign(data []byte) []byte {
	return ed25519.Sign(signingKey.Private, data)
}

// ToVerificationKey returns the verification key corresponding to signingKey.
func (signingKey *SigningKey) ToVerificationKey() VerificationKey {
	verificationKey := VerificationKey{}
	verificationKey.Public = signingKey.Private.Public().(ed25519.PublicKey)
	return verificationKey
}

// VerificationKey is a the type of key used for verifying signatures and generating public addressess.
type VerificationKey struct {
	Key
	Public ed25519.PublicKey
}

// Hash returns the blake2b_256 hash of verificationkey.
func (verificationkey *VerificationKey) Hash() []byte {
	hash, _ := blake2b.New(VERIFICATION_KEY_HASH_SIZE, verificationkey.Public)
	return hash.Sum(nil)
}

// Verify reports whether signature is a valid signature of message by verificationKey.
func (verificationKey *VerificationKey) Verify(data []byte, signature []byte) bool {
	return ed25519.Verify(verificationKey.Public, data, signature)
}

// PaymentKeyPair is the type that contains a payment signing key and a payment verification key.
type PaymentKeyPair struct {
	VerificationKey VerificationKey
	SigningKey      SigningKey
}

// GeneratePaymentKeyPair generates a payment signing/verification key pair.
func GeneratePaymentKeyPair() *PaymentKeyPair {
	signingKey, verificationKey := GenerateKeys()
	paymentKeyPair := &PaymentKeyPair{
		SigningKey:      signingKey,
		VerificationKey: verificationKey,
	}
	paymentKeyPair.SigningKey.KeyType = PAYMENT_SIGNING_KEY
	paymentKeyPair.SigningKey.Description = "Payment Signing Key"
	paymentKeyPair.SigningKey.CborHex = hex.EncodeToString([]byte(paymentKeyPair.SigningKey.Private))

	paymentKeyPair.VerificationKey.KeyType = PAYMENT_VERIFICATION_KEY
	paymentKeyPair.VerificationKey.Description = "Payment Verification Key"
	paymentKeyPair.VerificationKey.CborHex = hex.EncodeToString([]byte(paymentKeyPair.VerificationKey.Public))

	return paymentKeyPair
}
