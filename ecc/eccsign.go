package ecc

import (
	"crypto/ecdsa"
	rand "lukechampine.com/frand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"runtime"

	"github.com/3JoB/ulib/hex"
	log "github.com/sirupsen/logrus"

	"github.com/3JoB/ulib/crypt/hash"
)

func sign(msg []byte, priKey []byte) (rSign []byte, sSign []byte, err error) {
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
	privateKey, err := x509.ParseECPrivateKey(priKey)
	if err != nil {
		return nil, nil, err
	}
	resultHash := hash.SHA256(msg).Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, resultHash)
	if err != nil {
		return nil, nil, err
	}

	rText, err := r.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	sText, err := s.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	return rText, sText, nil
}

func verifySign(msg []byte, pubKey []byte, rText, sText []byte) bool {
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
	publicKeyInterface, _ := x509.ParsePKIXPublicKey(pubKey)
	publicKey := publicKeyInterface.(*ecdsa.PublicKey)
	resultHash := hash.SHA256(msg).Sum(nil)

	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	result := ecdsa.Verify(publicKey, resultHash, &r, &s)
	return result
}

func SignBase64(msg []byte, base64PriKey string) (base64rSign, base64sSign string, err error) {
	priBytes, err := base64.StdEncoding.DecodeString(base64PriKey)
	if err != nil {
		return "", "", err
	}
	rSign, sSign, err := sign(msg, priBytes)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(rSign), base64.StdEncoding.EncodeToString(sSign), nil
}

func VerifySignBase64(msg []byte, base64rSign, base64sSign, base64PubKey string) bool {
	rSignBytes, err := base64.StdEncoding.DecodeString(base64rSign)
	if err != nil {
		return false
	}
	sSignBytes, err := base64.StdEncoding.DecodeString(base64sSign)
	if err != nil {
		return false
	}
	pubBytes, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		return false
	}
	return verifySign(msg, pubBytes, rSignBytes, sSignBytes)
}

func SignHex(msg []byte, hexPriKey string) (hexrSign, hexsSign string, err error) {
	priBytes, err := hex.DecodeString(hexPriKey)
	if err != nil {
		return "", "", err
	}
	rSign, sSign, err := sign(msg, priBytes)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(rSign), hex.EncodeToString(sSign), nil
}

func VerifySignHex(msg []byte, hexrSign, hexsSign, hexPubKey string) bool {
	rSignBytes, err := hex.DecodeString(hexrSign)
	if err != nil {
		return false
	}
	sSignBytes, err := hex.DecodeString(hexsSign)
	if err != nil {
		return false
	}
	pubBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return false
	}
	return verifySign(msg, pubBytes, rSignBytes, sSignBytes)
}
