package hash

import (
	"crypto/sha1"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type SHA1Hasher struct {
	salt string
}

func NewSHA1Hasher() (*SHA1Hasher, error) {
	obj := make(map[string]interface{})
	yamlFile, err := os.ReadFile("config/salt.yml")
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, obj)
	if err != nil {
		return nil, err
	}
	salt := obj["salt"].(string)

	return &SHA1Hasher{salt: salt}, nil
}

func (h *SHA1Hasher) Hash(password string) (string, error) {
	hash := sha1.New()
	if _, err := hash.Write([]byte(password)); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum([]byte(h.salt))), nil
}
