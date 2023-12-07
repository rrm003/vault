package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"cloud.google.com/go/pubsub"
	_ "github.com/go-sql-driver/mysql" // Use the appropriate driver for your database
	"github.com/gorilla/mux"
	"github.com/rrm003/valut/pkg/db"
	"github.com/rrm003/valut/pkg/gcp"
	"github.com/rrm003/valut/pkg/web"
	"google.golang.org/api/option"

	firebaseAdmin "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/appcheck"
	"firebase.google.com/go/v4/auth"
)

var (
	appCheck   *appcheck.Client
	authClient *auth.Client
)

func decodeJWT(jwt string) (map[string]interface{}, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, errors.New("Invalid JWT format")
	}

	payload, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do stuff here
		log.Println(r.RequestURI)
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}

func requireAppCheck(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	wrappedHandler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Auth key", r.Header[http.CanonicalHeaderKey("X-Firebase-AppCheck")])
		appCheckToken, ok := r.Header[http.CanonicalHeaderKey("X-Firebase-AppCheck")]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized."))
			return
		}

		token, err := authClient.VerifyIDToken(r.Context(), appCheckToken[0])
		if err != nil {
			fmt.Println("failed to get the token", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized."))
			return
		}

		fmt.Printf("token iD %+v\n", token)

		ctx := context.WithValue(r.Context(), "userid", token.UID)

		fmt.Println("token ID", token.UID)

		e := gcp.AuditEvent{
			UserID:    token.UID,
			Action:    r.URL.Path,
			IP:        r.RemoteAddr,
			Browser:   r.UserAgent(),
			Timestamp: time.Now(),
		}

		web.SendAudit(e)
		handler(w, r.WithContext(ctx))
	}

	return wrappedHandler
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Continue processing the request
		next.ServeHTTP(w, r)
	})
}

func main() {
	log.Print("starting web services")

	// os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "./valut-svc-firebase-adminsdk4.json")
	os.Setenv("DB_HOST", "34.70.210.195")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_USER", "postgres")
	os.Setenv("DB_PASSWORD", "loop@007")
	os.Setenv("DB_NAME", "vault-db")
	os.Setenv("PROJECT_ID", "vault-svc")

	ctx := context.Background()

	app := &web.AppSvc{}
	app.Ctx = ctx

	pgdb, err := db.StartDB()
	if err != nil {
		log.Printf("error starting the database %v", err)
		return
	}

	app.DB = pgdb

	var wait time.Duration
	flag.DurationVar(&wait, "graceful-timeout", time.Second*15, "the duration for which the server gracefully wait for existing connections to finish - e.g. 15s or 1m")
	flag.Parse()

	//valut-svc-firebase-adminsdk4
	opt := option.WithCredentialsFile("./valut-svc-firebase-adminsdk4.json")

	admin, err := firebaseAdmin.NewApp(ctx, nil, opt)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
		return
	}

	appCheck, err = admin.AppCheck(ctx)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
		return
	}

	// Create a Firebase auth client instance
	authClient, err = admin.Auth(ctx)
	if err != nil {
		log.Fatalf("Failed to create Firebase auth client: %v", err)
		return
	}

	app.AuthClient = authClient

	storageSvc, err := gcp.GetStorageSvc()
	if err != nil {
		fmt.Println("file create", "failed to get storage svc", err)
		return
	}

	profileStorageSvc, err := gcp.GetProfileStorageSvc()
	if err != nil {
		fmt.Println("file create", "failed to get storage svc", err)
		return
	}

	app.StorageSvc = storageSvc
	app.ProfileStorageSvc = profileStorageSvc

	projectID := "valut-svc" // Replace with your Google Cloud project ID
	topicID := "topic-otp"   // Replace with the Pub/Sub topic ID

	client, err := pubsub.NewClient(ctx, projectID, option.WithCredentialsFile("./valut-svc-firebase-adminsdk4.json"))
	if err != nil {
		fmt.Printf("Error creating Pub/Sub client: %v\n", err)
		return
	}
	defer client.Close()

	topicotp := client.Topic(topicID)
	app.TopicOTP = topicotp

	r := mux.NewRouter()
	r.Use(enableCORS)

	r.HandleFunc("/register", app.UserRegistration).Methods(http.MethodPost, http.MethodOptions)
	r.HandleFunc("/login", app.UserLogin).Methods(http.MethodPost, http.MethodOptions)

	r.HandleFunc("/user", requireAppCheck(app.UserUpdateHandler)).Methods(http.MethodPut, http.MethodOptions)
	r.HandleFunc("/user", requireAppCheck(app.UserFetchHandler)).Methods(http.MethodGet, http.MethodOptions)
	r.HandleFunc("/user", requireAppCheck(app.UserDeleteHandler)).Methods(http.MethodDelete, http.MethodOptions)

	r.HandleFunc("/list", requireAppCheck(app.FileListHandler)).Methods(http.MethodPost, http.MethodOptions)
	r.HandleFunc("/file/upload", requireAppCheck(app.FileCreateHandler)).Methods(http.MethodPost, http.MethodOptions)
	r.HandleFunc("/file", requireAppCheck(app.UserUpdateHandler)).Methods(http.MethodPut, http.MethodOptions)
	r.HandleFunc("/file/otp", requireAppCheck(app.FetchFileOTPHandler)).Methods(http.MethodPost, http.MethodOptions)
	r.HandleFunc("/file", requireAppCheck(app.FetchFileHandler)).Methods(http.MethodPost, http.MethodOptions)
	// r.HandleFunc("/file", app.FetchFileHandler).Methods(http.MethodPost, http.MethodOptions)

	r.HandleFunc("/file", requireAppCheck(app.FileDeleteHandler)).Methods(http.MethodDelete, http.MethodOptions)

	r.HandleFunc("/folder", requireAppCheck(app.CreateFolderHandler)).Methods(http.MethodPost, http.MethodOptions)

	r.HandleFunc("/profile/upload", requireAppCheck(app.UploadProfile)).Methods(http.MethodPost, http.MethodOptions)

	r.Use(loggingMiddleware)

	srv := &http.Server{
		Addr: "0.0.0.0:8080",
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r, // Pass our instance of gorilla/mux in.
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		} else {
			log.Print("server has started")
		}
	}()

	c := make(chan os.Signal, 1)

	signal.Notify(c, os.Interrupt)

	<-c

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	srv.Shutdown(ctx)

	log.Println("shutting down")
	os.Exit(0)
}

// kubectl create secret generic svc-credentials-secret --from-file=svc-credentials.json=./valut-svc-firebase-adminsdk4.json
