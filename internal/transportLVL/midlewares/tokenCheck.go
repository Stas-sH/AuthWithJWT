package midlewares

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt"
	"gopkg.in/yaml.v2"
)

func TokenCheck(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		token, err := getTokenFromRequest(r)
		if err != nil {
			log.Println("TokenCheck - getTokenFromRequest:", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userId, err := parseToken(token)
		if err != nil {
			log.Println("TokenCheck - parseToken:", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		//создаем контекст и закидываем туда айди юзера
		ctx := context.WithValue(r.Context(), "ctxUserId", userId)
		r = r.WithContext(ctx)

		next(w, r)
	}
}

func getTokenFromRequest(r *http.Request) (string, error) {
	header := r.Header.Get("Autorization")
	if header == "" {
		return "", errors.New("empty auth header")
	}

	headerParts := strings.Split(header, " ")
	if len(headerParts) != 2 || headerParts[0] != "Bearer" {
		return "", errors.New("invalid auth header")
	}
	if len(headerParts[1]) == 0 {
		return "", errors.New("token is empty")
	}

	return headerParts[1], nil
}

func parseToken(token string) (int, error) {
	//достаем секрет
	obj := make(map[string]interface{})
	yamlFile, err := os.ReadFile("config/secret.yml")
	if err != nil {
		return 0, err
	}

	err = yaml.Unmarshal(yamlFile, obj)
	if err != nil {
		return 0, err
	}

	hmacSecret := obj["secret"].(string)

	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(hmacSecret), nil
	})
	if err != nil {
		return 0, err
	}

	if !t.Valid {
		return 0, errors.New("invalid token")
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errors.New("invalid claims")
	}

	subject, ok := claims["sub"].(string)
	if !ok {
		return 0, errors.New("invalid subject")
	}

	id, err := strconv.Atoi(subject)
	if err != nil {
		return 0, errors.New("invalid subject")
	}

	return id, nil

}
