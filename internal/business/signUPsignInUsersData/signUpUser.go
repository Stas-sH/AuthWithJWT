package signupsigninusersdata

import "github.com/go-playground/validator"

type SignUpUserInput struct {
	UserName string `json:"name" validate:"required,gte=2"`
	Mail     string `json:"mail" validate:"required,email"`
	Phone    string `json:"phone" validate:""`
	Password string `json:"password" validate:"required,gte=6"`
}

func (userInput SignUpUserInput) Validate() error {
	validate := validator.New()
	return validate.Struct(userInput)
}
