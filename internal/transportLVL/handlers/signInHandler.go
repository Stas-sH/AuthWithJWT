package handlers

import (
	signinusersdata "Stas-sH/RegAuthJWT/internal/business/signUPsignInUsersData"
	"Stas-sH/RegAuthJWT/internal/business/tokens"
	"Stas-sH/RegAuthJWT/internal/db"
	"Stas-sH/RegAuthJWT/pkg/hash"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func SignInHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		signIn(w, r)
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

func signIn(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("signIn - ReadAll:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var inp signinusersdata.SignInUserInput
	if err = json.Unmarshal(body, &inp); err != nil {
		log.Println("signIn - Unmarshal:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err = inp.Validate(); err != nil {
		log.Println("signIn - Validate:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hasher, err := hash.NewSHA1Hasher()
	if err != nil {
		log.Println("signIn - NewSHA1Hasher:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	inp.Password, err = hasher.Hash(inp.Password)
	if err != nil {
		log.Println("signIn - Hash:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userInfo, err := db.GetUserFromDB(inp)
	if err != nil {
		log.Println("signIn - GetUserFromDB", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if userInfo.Id < 0 {
		log.Println("user with such credentials not found")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	accessToken, refreshToken, err := tokens.GenerateTokens(userInfo.Id)
	if err != nil {
		log.Println("signIn - GenerateToken:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(map[string]string{"token": accessToken})
	if err != nil {
		log.Println("signIn - Marshal", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Set-Cookie", fmt.Sprintf("refresh-token=%s; HttpOnly", refreshToken))
	w.Header().Add("Content-Type", "application/json")
	w.Write(response)

}
