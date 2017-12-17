package config

import (
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v2"
)

type Config struct {
	FrontendURL       string `yaml:"frontend-url"`
	CoreURL           string `yaml:"core-url"`
	RedirectURI       string `yaml:"redirect-uri"`
	InstagramClientID string `yaml:"instagram-client-id"`
	InstagramSecret   string `yaml:"instagram-secret"`
}

// TODO: Add validation to avoid empty values
func New(path string) (*Config, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("Unable to create config file: %v", err)
		return nil, err
	}

	conf := &Config{}
	if err := yaml.Unmarshal(contents, conf); err != nil {
		log.Printf("Unable to create config file: %v", err)
		return nil, err
	}

	return conf, nil
}
