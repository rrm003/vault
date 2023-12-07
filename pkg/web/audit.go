package web

import (
	"context"
	"fmt"

	"cloud.google.com/go/pubsub"
	"github.com/rrm003/valut/pkg/gcp"
	"google.golang.org/api/option"
)

func SendAudit(event gcp.AuditEvent) {
	projectID := "valut-svc" // Replace with your Google Cloud project ID
	topicID := "topic-audit" // Replace with the Pub/Sub topic ID
	ctx := context.Background()

	client, err := pubsub.NewClient(ctx, projectID, option.WithCredentialsFile("./valut-svc-firebase-adminsdk4.json"))
	if err != nil {
		fmt.Printf("Error creating Pub/Sub client: %v\n", err)
		return
	}
	defer client.Close()

	topicaudit := client.Topic(topicID)

	fmt.Printf("sending event %+v\n", event)

	err = gcp.PublishAudit(ctx, topicaudit, &event)
	if err != nil {
		fmt.Println("failed to publish msg", err)

		return
	}
}
