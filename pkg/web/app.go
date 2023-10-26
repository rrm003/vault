package web

import (
	"log"

	"firebase.google.com/go/v4/auth"
	"github.com/go-pg/pg/v10"
)

type AppSvc struct {
	DB         *pg.DB
	Logger     *log.Logger
	AuthClient *auth.Client
}
