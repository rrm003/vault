package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"cloud.google.com/go/pubsub"
	"google.golang.org/api/option"
)

type Event struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Msg   string `json:"msg"`
}

type AuditEvent struct {
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"`
	IP        string    `json:"ip"`
	Browser   string    `json:"browser"`
	Timestamp time.Time `json:"timestamp"`
}

func GetPubSvc(ctx context.Context) (*pubsub.Client, error) {
	fmt.Println("publishing msg for ", projectID)

	client, err := pubsub.NewClient(ctx, "valut-svc", option.WithCredentialsFile("./valut-svc-firebase-adminsdk4.json"))
	if err != nil {
		fmt.Printf("Error creating Pub/Sub client: %v\n", err)
		return nil, err
	}

	defer client.Close()

	return client, nil
}

func PublishMessage(ctx context.Context, t *pubsub.Topic, e *Event) error {
	fmt.Printf("received event %+v\n", e)

	msg, err := json.Marshal(e)
	if err != nil {
		fmt.Println("failed to marshal event", err)
		return err
	}

	result := t.Publish(ctx, &pubsub.Message{
		Data: []byte(msg),
	})

	id, err := result.Get(ctx)
	if err != nil {
		return fmt.Errorf("pubsub: result.Get: %w", err)
	}

	fmt.Printf("Published a message; msg ID: %v\n", id)
	return nil
}

func PublishAudit(ctx context.Context, t *pubsub.Topic, e *AuditEvent) error {
	fmt.Printf("received event %+v\n", e)

	msg, err := json.Marshal(e)
	if err != nil {
		fmt.Println("failed to marshal event", err)
		return err
	}

	result := t.Publish(ctx, &pubsub.Message{
		Data: []byte(msg),
	})

	id, err := result.Get(ctx)
	if err != nil {
		return fmt.Errorf("pubsub: result.Get: %w", err)
	}

	fmt.Printf("Published a message; msg ID: %v\n", id)
	return nil
}
