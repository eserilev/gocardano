package key

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

var signingKey SigningKey = SigningKey{}
var verificationKey VerificationKey = VerificationKey{}
var testMessage, _ = hex.DecodeString("26a0a47f733d02ddb74589b6cbd6f64a7dab1947db79395a1a9e00e4c902c0f185b119897b89b248d16bab4ea781b5a3798d25c2984aec833dddab57e0891e0d68656c6c6f20776f726c64")

var testSigningKey = "749026cce1c1544bd8d63043acb63f91fca63e444985739950455fe90b6d7e32d5bfb069eb3da218875a6caafa27e16ad01fc3408b90052741928337f8a0bdcb"
var testSignedMessage, _ = hex.DecodeString("2fdd5f3a9029db02eddeaed7fa02c9526bcf24ef05e423b807f78967a5be2533dcba10d1ec596dd7ea3d9155ed07e9a9fc70b9cf69de21acaa0cd73be9c1d201")

func init() {
	signingKey, verificationKey = GenerateKeys()
}

func TestGeneratePaymentKeyPair(t *testing.T) {
	paymentKeyPair := GeneratePaymentKeyPair()
	if paymentKeyPair == nil {
		t.Fatalf("GeneratePaymentKeyPair failed")
	}
}

func TestJson(t *testing.T) {
	paymentKeyPair := GeneratePaymentKeyPair()
	j := paymentKeyPair.VerificationKey.Key.ToJson()

	if j == nil {
		t.Fatalf("ToJson failed")
	}

	obj := FromJson(j)

	if len(obj.CborHex) == 0 {
		t.Fatalf("FromJson failed")
	}
}

func TestSign(t *testing.T) {
	key, _ := hex.DecodeString(testSigningKey)
	privateKey := ed25519.PrivateKey(key)
	signingKey := SigningKey{}
	signingKey.Private = privateKey

	signedMessage := signingKey.Sign(testMessage)

	if !bytes.Equal(signedMessage, testSignedMessage) {
		t.Fatalf("signed message did not match, got\n%x\n, expected\n%x", signedMessage, testSignedMessage)
	}
}

func TestSignWithGeneratedKey(t *testing.T) {
	signedMessage := signingKey.Sign(testMessage)

	if signedMessage == nil {
		t.Fatalf("signed message failed")
	}

	signedMessage2 := signingKey.Sign(testMessage)
	if !bytes.Equal(signedMessage, signedMessage2) {
		t.Fatalf("signed message did not match, got\n%x\n, expected\n%x", signedMessage, signedMessage2)
	}
}

func TestVerifiyWithGeneratedKey(t *testing.T) {
	signedMessage := signingKey.Sign(testMessage)
	if !verificationKey.Verify(testMessage, signedMessage) {
		t.Fatalf("verification failed")
	}
}

func TestHashWithGeneratedKey(t *testing.T) {
	hash := verificationKey.Hash()
	if hash == nil {
		t.Fatalf("hash message failed")
	}
}

func TestDifferentSignatures(t *testing.T) {
	signingKey2, _ := GenerateKeys()
	signedMessage := signingKey.Sign(testMessage)
	signedMessage2 := signingKey2.Sign(testMessage)

	if bytes.Equal(signedMessage, signedMessage2) {
		t.Fatalf("signed message did not match, got\n%x\n, expected\n%x", signedMessage, signedMessage2)
	}
}
