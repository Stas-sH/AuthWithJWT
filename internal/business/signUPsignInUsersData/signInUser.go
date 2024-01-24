package signupsigninusersdata

import "github.com/go-playground/validator"

type SignInUserInput struct {
	Mail     string `json:"mail" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=6"`
}

func (userInput SignInUserInput) Validate() error {
	validate := validator.New()
	return validate.Struct(userInput)
}
