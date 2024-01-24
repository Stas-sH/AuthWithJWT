package db

import (
	signupusersdata "Stas-sH/RegAuthJWT/internal/business/signUPsignInUsersData"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

func CreateUserInDB(u signupusersdata.SignUpUserInput) error {

	err := DbConfigs.SetConfig()
	if err != nil {
		return err
	}

	db, err := sql.Open(DbConfigs.Name, fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=%s password=%s", DbConfigs.Host, DbConfigs.Port, DbConfigs.User, DbConfigs.DbName, DbConfigs.SSLmode, DbConfigs.Password))
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		return err
	}
	////////////////////////////////////////////////////
	err = insertUser(db, u)
	if err != nil {
		return err
	}

	return nil
}

func insertUser(db *sql.DB, u signupusersdata.SignUpUserInput) error {
	_, err := db.Exec("insert into users (username, mail, phone, password, registered_at) values ($1, $2, $3, $4, $5)", u.UserName, u.Mail, u.Phone, u.Password, time.Now())
	return err
}
