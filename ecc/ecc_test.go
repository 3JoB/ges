package ecc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	msg          = "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	base64PubKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElJ+LbZBekYTu/Md4T/j3DJsmJFf/3wLLmfUR7sLXCzS1PsDpHIC0QXRdVVdzS9BmP5GdtpesR4Oeh7g0TBBoLA=="
	base64PriKey = "MHcCAQEEIKPH4RlH9IQYwalxykgwlZkV9JjxQW2mHM+oGp4dxkMGoAoGCCqGSM49AwEHoUQDQgAElJ+LbZBekYTu/Md4T/j3DJsmJFf/3wLLmfUR7sLXCzS1PsDpHIC0QXRdVVdzS9BmP5GdtpesR4Oeh7g0TBBoLA=="

	hexPubKey = "3059301306072a8648ce3d020106082a8648ce3d030107034200043d39b48322518e8c6053ff63ef0426537fb1d5e16d128802c4c54104d61f84605b6bfa3266cc7f38968c0174d672e3690e50a93c819589f6d0f6bb44a57bcee8"
	hexPriKey = "30770201010420af9497e1c61ffe6019592a25f22a12e079e87d935b01bd2dc6d817744053a849a00a06082a8648ce3d030107a144034200043d39b48322518e8c6053ff63ef0426537fb1d5e16d128802c4c54104d61f84605b6bfa3266cc7f38968c0174d672e3690e50a93c819589f6d0f6bb44a57bcee8"
)

func TestEccEncryptBase64(t *testing.T) {
	base64Key, err := GenerateKeyBase64()
	assert.Nil(t, err)

	cipherText, err := EncryptToBase64([]byte(msg), base64PubKey)
	assert.Nil(t, err)
	_, err = EncryptToBase64([]byte(msg), base64PriKey)
	assert.NotNil(t, err)
	plainText, err := DecryptByBase64(cipherText, base64PriKey)
	assert.Nil(t, err)
	assert.Equal(t, msg, string(plainText))

	cipherText, err = EncryptToBase64([]byte(msg), base64Key.PublicKey)
	assert.Nil(t, err)
	plainText, err = DecryptByBase64(cipherText, base64Key.PrivateKey)
	assert.Nil(t, err)
	assert.Equal(t, msg, string(plainText))
	_, err = DecryptByBase64(cipherText, base64Key.PublicKey)
	assert.NotNil(t, err)
	_, err = DecryptByBase64("badText", base64Key.PrivateKey)
	assert.NotNil(t, err)
	_, err = DecryptByBase64(cipherText, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElJ")
	assert.NotNil(t, err)
}

func TestEccEncryptHex(t *testing.T) {
	hexKey, err := GenerateKeyHex()
	assert.Nil(t, err)

	cipherText, err := EncryptToHex([]byte(msg), hexPubKey)
	assert.Nil(t, err)
	_, err = EncryptToHex([]byte(msg), hexPriKey)
	assert.NotNil(t, err)
	plainText, err := DecryptByHex(cipherText, hexPriKey)
	assert.Nil(t, err)
	assert.Equal(t, msg, string(plainText))

	cipherText, err = EncryptToHex([]byte(msg), hexKey.PublicKey)
	assert.Nil(t, err)
	plainText, err = DecryptByHex(cipherText, hexKey.PrivateKey)
	assert.Nil(t, err)
	assert.Equal(t, msg, string(plainText))
	_, err = DecryptByHex(cipherText, hexKey.PublicKey)
	assert.NotNil(t, err)
	_, err = DecryptByHex("badText", hexKey.PrivateKey)
	assert.NotNil(t, err)
	_, err = DecryptByHex(cipherText, "3059301306072a8648ce3d020106082a8648ce3d03")
	assert.NotNil(t, err)
}

func TestSignBase64(t *testing.T) {
	base64Key, err := GenerateKeyBase64()
	assert.Nil(t, err)

	rText, sText, err := SignBase64([]byte(msg), base64Key.PrivateKey)
	assert.Nil(t, err)
	_, _, err = SignBase64([]byte(msg), base64Key.PublicKey)
	assert.NotNil(t, err)
	_, _, err = SignBase64([]byte(msg), base64PubKey)
	assert.NotNil(t, err)

	res := VerifySignBase64([]byte(msg), rText, sText, base64Key.PublicKey)
	assert.Equal(t, res, true)

	res = VerifySignBase64([]byte(msg), rText, sText, base64Key.PrivateKey)
	assert.Equal(t, res, false)
	res = VerifySignBase64([]byte(msg), sText, rText, base64Key.PrivateKey)
	assert.Equal(t, res, false)
}

func TestSignHex(t *testing.T) {
	hexKey, err := GenerateKeyHex()
	assert.Nil(t, err)

	rText, sText, err := SignHex([]byte(msg), hexKey.PrivateKey)
	assert.Nil(t, err)
	_, _, err = SignHex([]byte(msg), hexKey.PublicKey)
	assert.NotNil(t, err)
	_, _, err = SignHex([]byte(msg), hexPubKey)
	assert.NotNil(t, err)

	res := VerifySignHex([]byte(msg), rText, sText, hexKey.PublicKey)
	assert.Equal(t, res, true)

	res = VerifySignHex([]byte(msg), rText, sText, hexKey.PrivateKey)
	assert.Equal(t, res, false)
	res = VerifySignHex([]byte(msg), sText, rText, hexKey.PrivateKey)
	assert.Equal(t, res, false)
}
