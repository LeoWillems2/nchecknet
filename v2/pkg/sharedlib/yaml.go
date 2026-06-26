

package sharedlib

import (
	"fmt"
	"os"
    	"gopkg.in/yaml.v2"
)

// YamlConfig holds the entire nchecknet.yml configuration.
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
	Webroot string    `yaml:"webroot"`
}

// CollectorConfig holds the collector-specific settings.
type CollectorConfig struct {
	CollectorURL string `yaml:"collectorurl"`
	Port string    `yaml:"port"`
}

// GetYamlConfig reads and parses the YAML config file at configPath.
// If the file is not found there it retries under /usr/local/<configPath>.
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
