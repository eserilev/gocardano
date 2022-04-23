package key

import (
	"crypto/ed25519"

	"golang.org/x/crypto/blake2b"
)

const (
	VERIFICATION_KEY_HASH_SIZE = 28
)

type Key struct {
}

func (key *Key) ToJson() {

}

func (key *Key) FromJson() {

}

func (key *Key) FromFile() {

}

func (key *Key) ToFile() {

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
