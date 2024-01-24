package usersdata

import "time"

type User struct {
	Id           int       `json:"id"`
	UserName     string    `json:"name"`
	Mail         string    `json:"mail"`
	Phone        string    `json:"phone"`
	Password     string    `json:"password"`
	RegisteredAt time.Time `json:"registered_at"`
}
