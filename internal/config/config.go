package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	Env             string        `yaml:"env" env-default:"development"`
	DB              DBConfig      `yaml:"db" env-required:"true"`
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl" env-required:"true"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" env-required:"true"`
	GRPC            GRPCConfig    `yaml:"grpc"`
}

type GRPCConfig struct {
	Port      int    `yaml:"port"`
	Timeout   string `yaml:"timeout"`
	PublicKey string
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
	if err := godotenv.Load(); err != nil {
		panic("Error loading .env file")
	}

	var res string
	res = os.Getenv("CONFIG_PATH")
	if res == "" {
		panic("CONFIG_PATH must be set")
	}
	return MustLoadByPath(res)
}

func MustLoadByPath(path string) *Config {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		absPath, _ := filepath.Abs(path)
		panic("CONFIG_PATH does not exist: " + absPath)
	}

	var dbPath string
	dbPath = os.Getenv("DB_PASS")
	if dbPath == "" {
		panic("DB_PASS must be set")
	}

	var jwtKey string
	jwtKey = os.Getenv("JWT_PUBLIC_KEY")
	if jwtKey == "" {
		panic("JWT_PUBLIC_KEY must be set")
	}

	var cfg Config
	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		panic(err)
	}

	cfg.DB.Password = dbPath
	cfg.GRPC.PublicKey = jwtKey

	return &cfg
}
