package db

import (
	"os"

	"gopkg.in/yaml.v2"
)

type DbConfig struct {
	Name     string
	Host     string
	Port     string
	User     string
	DbName   string
	SSLmode  string
	Password string
}

var DbConfigs DbConfig

func (db *DbConfig) SetConfig() error {
	obj := make(map[string]interface{})
	yamlFile, err := os.ReadFile("config/dbconfig.yml")
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(yamlFile, obj)
	if err != nil {
		return err
	}

	db.Name = obj["name"].(string)
	db.Host = obj["host"].(string)
	db.Port = obj["port"].(string)
	db.User = obj["user"].(string)
	db.DbName = obj["dbname"].(string)
	db.SSLmode = obj["sslmode"].(string)
	db.Password = obj["password"].(string)

	return nil
}
