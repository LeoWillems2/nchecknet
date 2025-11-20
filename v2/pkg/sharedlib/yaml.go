

package sharedlib

import (
	"fmt"
	"os"
	"log"
	"gopkg.in/yaml.v2"
)

// Config holds the entire configuration structure.
type YamlConfig struct {
	Server   ServerConfig   `yaml:"server"`
}

// ServerConfig holds the server-specific settings.
type ServerConfig struct {
	CollectorURL string `yaml:"collectorurl"`
	JWTSecret string    `yaml:"jwtsecret"`
}

func GetYamlConfig(configPath string) (YamlConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return YamlConfig{}, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	var cfg YamlConfig
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return YamlConfig{}, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	return cfg, nil
}

func TestYaml() {
	// The path to our configuration file
	configPath := "etc/nchecknet.yml"

	// Call the function to initialize and read the config
	config, err := GetYamlConfig(configPath)
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// Print the loaded configuration details
	fmt.Println("✅ Configuration loaded successfully!")
	fmt.Println("---")

	fmt.Println(config.Server)
}
