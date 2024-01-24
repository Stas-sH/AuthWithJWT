package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"Stas-sH/RegAuthJWT/internal/business/tokens"
	"Stas-sH/RegAuthJWT/internal/db"
)

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		refreshUpdate(w, r)
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

func refreshUpdate(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("refresh-token")
	if err != nil {
		log.Println("refreshUpdate - Cookie:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := getTokens(r.Context(), cookie.Value)
	if err != nil {
		log.Println("refreshUpdate - getTokens", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(map[string]string{
		"token": accessToken,
	})
	if err != nil {
		log.Println("refreshUpdate - Marshal:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Set-Cookie", fmt.Sprintf("refresh-token='%s'; HttpOnly", refreshToken))
	w.Header().Add("Content-Type", "application/json")
	w.Write(response)

}

func getTokens(ctx context.Context, refreshToken string) (string, string, error) {
	session, err := db.GetRefreshFromDB(refreshToken)
	if err != nil {
		return "", "", err
	}

	if session.ExpiresAt.Unix() < time.Now().Unix() {
		return "", "", errors.New("refresh token expired")
	}

	userAccessToken, refreshToken, err := tokens.GenerateTokens(session.UserID)
	if err != nil {
		return "", "", err
	}

	return userAccessToken, refreshToken, nil
}
