package web

import (
	"context"
	"log"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"firebase.google.com/go/v4/auth"
	"github.com/go-pg/pg/v10"
)

type AppSvc struct {
	Ctx               context.Context
	DB                *pg.DB
	Logger            *log.Logger
	AuthClient        *auth.Client
	StorageSvc        *storage.BucketHandle
	ProfileStorageSvc *storage.BucketHandle

	TopicOTP   *pubsub.Topic
	TopicAudit *pubsub.Topic
}
