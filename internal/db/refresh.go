package db

import (
	"Stas-sH/RegAuthJWT/internal/business/refresh"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func NewRefreshSession(user_id int, token string) error {
	var newRefreshSession refresh.RefreshSession = refresh.RefreshSession{
		UserID:    user_id,
		Token:     token,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 30),
	}

	if err := createRefreshInDB(newRefreshSession); err != nil {
		return err
	}
	return nil
}

func createRefreshInDB(r refresh.RefreshSession) error {

	if err := DbConfigs.SetConfig(); err != nil {
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
	///////////////////////////////////////////////

	if err = insertRefresh(db, r); err != nil {
		return err
	}

	return nil

}

func insertRefresh(db *sql.DB, r refresh.RefreshSession) error {
	_, err := db.Exec("INSERT INTO refresh_tokens (user_id, token, expires_at) values ($1, $2, $3)", r.UserID, r.Token, r.ExpiresAt)
	if err != nil {
		return err
	}

	return nil
}

func GetRefreshFromDB(token string) (refresh.RefreshSession, error) {
	var tokenInfo refresh.RefreshSession

	if err := DbConfigs.SetConfig(); err != nil {
		return tokenInfo, err
	}

	db, err := sql.Open(DbConfigs.Name, fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=%s password=%s", DbConfigs.Host, DbConfigs.Port, DbConfigs.User, DbConfigs.DbName, DbConfigs.SSLmode, DbConfigs.Password))
	if err != nil {
		return tokenInfo, err
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		return tokenInfo, err
	}
	///////////////////////////////////////////////
	tokenInfo, err = selectRefresh(db, token)
	if err != nil {
		return tokenInfo, err
	}

	///////////////////////////////////////////////
	err = dleteToken(db, int(tokenInfo.UserID))
	if err != nil {
		return tokenInfo, err
	}

	return tokenInfo, nil
}

func selectRefresh(db *sql.DB, token string) (refresh.RefreshSession, error) {
	var tokenInfo refresh.RefreshSession

	err := db.QueryRow("SELECT id, user_id, token, expires_at FROM refresh_tokens WHERE token=$1", token).Scan(&tokenInfo.ID, &tokenInfo.UserID, &tokenInfo.Token, &tokenInfo.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			tokenInfo.ID = -1
			return tokenInfo, nil
		}
		return tokenInfo, err
	}

	return tokenInfo, nil
}

func dleteToken(db *sql.DB, user_id int) error {

	_, err := db.Exec("DELETE FROM refresh_tokens WHERE user_id=$1", user_id)

	if err != nil {
		return err
	}

	return nil
}

func DeleteRefreshInDB(user_id int) error {

	if err := DbConfigs.SetConfig(); err != nil {
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
	//////////////////////////////////////////////////////

	if err = dleteToken(db, user_id); err != nil {
		return err
	}

	return nil
}
