package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
	"os"
	"time"
)

type Config struct {
	Env      string        `yaml:"env" env-default:"development"`
	DB       DBConfig      `yaml:"db" env-required:"true"`
	TokenTTL time.Duration `yaml:"token_ttl" env-required:"true"`
	GRPC     GRPCConfig    `yaml:"grpc"`
}

type GRPCConfig struct {
	Port    int    `yaml:"port"`
	Timeout string `yaml:"timeout"`
}

type DBConfig struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	User     string `yaml:"user"`
	Password string
	Database string `yaml:"database"`
	SSLMode  string `yaml:"ssl_mode"`
}

func MustLoad() *Config {
	var res string
	var dbPass string

	if err := godotenv.Load(); err != nil {
		panic("Error loading .env file")
	}

	res = os.Getenv("CONFIG_PATH")
	if res == "" {
		panic("CONFIG_PATH must be set")
	}

	dbPass = os.Getenv("DB_PASS")
	if dbPass == "" {
		panic("CONFIG_PATH must be set")
	}

	if _, err := os.Stat(res); os.IsNotExist(err) {
		panic("CONFIG_PATH does not exist")
	}

	var cfg Config

	if err := cleanenv.ReadConfig(res, &cfg); err != nil {
		panic(err)
	}

	cfg.DB.Password = os.Getenv("DB_PASS")
	return &cfg

}
