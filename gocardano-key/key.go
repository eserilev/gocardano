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

type Key struct {
	KeyType     KeyType
	Description string
	CborHex     string
}

type KeyType string

const (
	PAYMENT_SIGNING_KEY      KeyType = "PaymentSigningKeyShelley_ed25519"
	PAYMENT_VERIFICATION_KEY KeyType = "PaymentVerificationKeyShelley_ed25519"
)

func (key *Key) ToJson() []byte {
	k := &JsonKey{
		Type:        string(key.KeyType),
		Description: key.Description,
		CborHex:     key.CborHex,
	}

	jsonKey, _ := json.Marshal(k)

	return jsonKey
}

func FromJson(data []byte) JsonKey {
	jsonKey := &JsonKey{}
	json.Unmarshal(data, jsonKey)
	return *jsonKey
}

func GenerateKeys() (SigningKey, VerificationKey) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		// TODO
	}

	verificationKey := &VerificationKey{
		Public: public,
	}

	signingKey := &SigningKey{
		Private: private,
	}

	return *signingKey, *verificationKey
}

type SigningKey struct {
	Key
	Private ed25519.PrivateKey
}

func (key *SigningKey) Sign(data []byte) []byte {
	return ed25519.Sign(key.Private, data)
}

func (key *SigningKey) ToVerificationKey() VerificationKey {
	verificationKey := VerificationKey{}
	verificationKey.Public = key.Private.Public().(ed25519.PublicKey)
	return verificationKey
}

type VerificationKey struct {
	Key
	Public ed25519.PublicKey
}

func (key *VerificationKey) Hash() []byte {
	hash, err := blake2b.New(VERIFICATION_KEY_HASH_SIZE, key.Public)
	if err != nil {
		return nil
	}

	return hash.Sum(nil)
}

func (key *VerificationKey) Verify(data []byte, signature []byte) bool {
	return ed25519.Verify(key.Public, data, signature)
}

type PaymentKeyPair struct {
	VerificationKey VerificationKey
	SigningKey      SigningKey
}

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

type JsonKey struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CborHex     string `json:"cborHex"`
}
