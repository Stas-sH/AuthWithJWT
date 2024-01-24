package tokens

import (
	"Stas-sH/RegAuthJWT/internal/business/refresh"

	"Stas-sH/RegAuthJWT/internal/db"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"gopkg.in/yaml.v2"
)

func GenerateTokens(userId int) (string, string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Subject:   strconv.Itoa(userId),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Minute * 30).Unix(),
	})

	//достаем секрет
	obj := make(map[string]interface{})
	yamlFile, err := os.ReadFile("config/secret.yml")
	if err != nil {
		return "", "", err
	}

	err = yaml.Unmarshal(yamlFile, obj)
	if err != nil {
		return "", "", err
	}

	secret := obj["secret"].(string)

	userAccessToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", "", err
	}
	////////////////////////////////////////////////////////////////////////

	refreshToken, err := refresh.NewRefreshToken()
	if err != nil {
		return "", "", err
	}

	if err = db.NewRefreshSession(userId, refreshToken); err != nil { ///думаю это нужно сделать в конце
		return "", "", err
	}

	return userAccessToken, refreshToken, nil
}
