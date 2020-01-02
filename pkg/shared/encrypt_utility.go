package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared/logging"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var ConfigFile string
var filePath string

func getKey() string {
	dir, _ := filepath.Split(ConfigFile)
	filePath = dir + ".enc.key"

	value, exists := os.LookupEnv("R7_ENCRYPTION_KEY")
	if !exists {
		fileBytes, err := ioutil.ReadFile(filePath)

		if err != nil {
			logging.Logger.Info("No encryption key found in file or as environment variable")
			generateKey()

			return getKey()
		}

		value = string(fileBytes)
	}
	return value
}

func generateKey() {
	key := make([]byte, 64)
	rand.Read(key)

	err := ioutil.WriteFile(filePath, []byte(base64.RawURLEncoding.EncodeToString(key)), 0400)
	if err != nil {
		logging.Logger.Fatal(fmt.Sprintf("Failed to generate ecnryption key; unable to continue: %s", err))
	} else {
		logging.Logger.Info(fmt.Sprintf("Encryption key created and saved with 0400 permissions in %s", filePath))
	}
}

func createHash(key string) string {
	hash := sha256.Sum256([]byte(key))
	return string(hash[:])
}

func Encrypt(value string) string {
	block, _ := aes.NewCipher([]byte(createHash(getKey())))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	return fmt.Sprintf("(enc)%s", encodeBase64(ciphertext))
}

func Decrypt(value string) string {
	var data []byte
	if strings.HasPrefix(value, "(enc)") {
		value = strings.TrimPrefix(value, "(enc)")
		data = decodeBase64(value)
	} else {
		return value
	}

	key := []byte(createHash(getKey()))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		logging.Logger.Error(fmt.Sprintf("Failed to decrypt, setting to empty string: %s", err))
		return ""
	}
	return string(plaintext)
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBase64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil { panic(err) }
	return data
}
