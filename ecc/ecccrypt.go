package ecc

import (
	"crypto/ecdsa"
	rand "lukechampine.com/frand"
	"crypto/x509"
	"encoding/base64"
	"runtime"

	"github.com/3JoB/ulib/hex"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetReportCaller(true)
}

// The public key and plaintext are passed in for encryption
func encrypt(plainText, pubKey []byte) (cipherText []byte, err error) {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Errorf("runtime err=%v,Check that the key or text is correct", err)
			default:
				log.Errorf("error=%v,check the cipherText ", err)
			}
		}
	}()
	tempPublicKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	// Decode to get the private key in the ecdsa package
	publicKey1 := tempPublicKey.(*ecdsa.PublicKey)
	// Convert to the public key in the ecies package in the ethereum package
	publicKey := ImportECDSAPublic(publicKey1)
	cipherText, err = Encrypt(rand.Reader, publicKey, plainText, nil, nil)
	return cipherText, err
}

// The private key and plaintext are passed in for decryption
func decrypt(cipherText, priKey []byte) (msg []byte, err error) {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Errorf("runtime err=%v,Check that the key or text is correct", err)
			default:
				log.Errorf("error=%v,check the cipherText ", err)
			}
		}
	}()
	tempPrivateKey, err := x509.ParseECPrivateKey(priKey)
	if err != nil {
		return nil, err
	}
	// Decode to get the private key in the ecdsa package
	// Convert to the private key in the ecies package in the ethereum package
	privateKey := ImportECDSA(tempPrivateKey)
	plainText, err := privateKey.Decrypt(cipherText, nil, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func EncryptToBase64(plainText []byte, base64PubKey string) (base64CipherText string, err error) {
	pub, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		return "", err
	}
	cipherBytes, err := encrypt(plainText, pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

func DecryptByBase64(base64CipherText, base64PriKey string) (plainText []byte, err error) {
	privateBytes, err := base64.StdEncoding.DecodeString(base64PriKey)
	if err != nil {
		return nil, err
	}
	cipherTextBytes, err := base64.StdEncoding.DecodeString(base64CipherText)
	if err != nil {
		return nil, err
	}
	return decrypt(cipherTextBytes, privateBytes)
}

func EncryptToHex(plainText []byte, hexPubKey string) (hexCipherText string, err error) {
	pub, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return "", err
	}
	cipherBytes, err := encrypt(plainText, pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(cipherBytes), nil
}

func DecryptByHex(hexCipherText, hexPriKey string) (plainText []byte, err error) {
	privateBytes, err := hex.DecodeString(hexPriKey)
	if err != nil {
		return nil, err
	}
	cipherTextBytes, err := hex.DecodeString(hexCipherText)
	if err != nil {
		return nil, err
	}
	return decrypt(cipherTextBytes, privateBytes)
}
