package main

import (
	"log"
	"net/http"

	"Stas-sH/RegAuthJWT/internal/transportLVL/handlers"
	"Stas-sH/RegAuthJWT/internal/transportLVL/midlewares"
)

func main() {
	http.HandleFunc("/users/signUp", handlers.SignUpHandler)
	http.HandleFunc("/users/signIn", handlers.SignInHandler)
	http.HandleFunc("/users/refresh", handlers.RefreshHandler)

	http.HandleFunc("/users/swaag", midlewares.TokenCheck(handlers.WaagHandler))

	if err := http.ListenAndServe(":8000", nil); err != nil {
		log.Fatal(err)
	}
}
