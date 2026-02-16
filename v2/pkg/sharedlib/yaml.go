

package sharedlib

import (
	"fmt"
	"os"
    "gopkg.in/yaml.v2"
)

// Config holds the entire configuration structure.
type YamlConfig struct {
	Server   ServerConfig   `yaml:"webserver"`
	Collector   CollectorConfig   `yaml:"collector"`
}

// ServerConfig holds the server-specific settings.
type ServerConfig struct {
	JWTSecret string    `yaml:"jwtsecret"`
	Port string    `yaml:"port"`
	MongoDBURL string    `yaml:"mongodburl"`
	MaxSessionIDSelect int   `yaml:"maxsessionidselect"`
}

// CollectorConfig holds the server-specific settings.
type CollectorConfig struct {
	CollectorURL string `yaml:"collectorurl"`
	Port string    `yaml:"port"`
}

func GetYamlConfig(configPath string) (YamlConfig, error) {

        data, err := os.ReadFile(configPath)
        if err != nil {
                configPath = "/usr/local/"+configPath
                data, err = os.ReadFile(configPath)
                if err != nil {
                        return YamlConfig{}, fmt.Errorf("failed to read config file %s: %w", configPath, err)
                }
        }


	var cfg YamlConfig
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return YamlConfig{}, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	return cfg, nil
}
