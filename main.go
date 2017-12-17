package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/iced-mocha/instagram-client/config"
	"github.com/iced-mocha/instagram-client/handlers"
	_ "github.com/iced-mocha/instagram-client/logging"
	"github.com/iced-mocha/instagram-client/server"
)

func main() {
	conf, err := config.New("config.yml")
	if err != nil {
		log.Fatalf("Unable to create config object: %v", err)
	}

	handler, err := handlers.New(conf)
	if err != nil {
		log.Fatalf("Unable to create handler: %v", err)
	}

	s, err := server.New(handler)
	if err != nil {
		log.Fatalf("error initializing server: %v", err)
	}

	srv := &http.Server{
		Addr:      ":3003",
		Handler:   s.Router,
		TLSConfig: &tls.Config{},
	}
	log.Fatal(srv.ListenAndServeTLS("/usr/local/etc/ssl/certs/instagram.crt", "/usr/local/etc/ssl/private/instagram.key"))
}
