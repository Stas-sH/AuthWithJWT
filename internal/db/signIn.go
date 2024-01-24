package db

import (
	signIndata "Stas-sH/RegAuthJWT/internal/business/signUPsignInUsersData"
	usersdata "Stas-sH/RegAuthJWT/internal/business/usersData"
	"database/sql"
	"errors"
	"fmt"
)

func GetUserFromDB(u signIndata.SignInUserInput) (usersdata.User, error) {
	var user usersdata.User

	if err := DbConfigs.SetConfig(); err != nil {
		return user, err
	}

	db, err := sql.Open(DbConfigs.Name, fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=%s password=%s", DbConfigs.Host, DbConfigs.Port, DbConfigs.User, DbConfigs.DbName, DbConfigs.SSLmode, DbConfigs.Password))
	if err != nil {
		return user, err
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		return user, err
	}
	////////////////////////////////////////////////////

	user, err = foundUser(db, u)
	if err != nil {
		return user, err
	}

	return user, nil
}

func foundUser(db *sql.DB, u signIndata.SignInUserInput) (usersdata.User, error) {
	var user usersdata.User
	err := db.QueryRow("select id, username, mail, phone, registered_at from users where mail=$1 and password=$2", u.Mail, u.Password).Scan(&user.Id, &user.UserName, &user.Mail, &user.Phone, &user.RegisteredAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			user.Id = -1
			return user, nil
		}
		return user, err
	}

	return user, nil
}
