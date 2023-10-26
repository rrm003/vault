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

	_ "github.com/go-sql-driver/mysql" // Use the appropriate driver for your database
	"github.com/gorilla/mux"
	"github.com/rrm003/valut/pkg/db"
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
		// claims, err := decodeJWT(appCheckToken[0])
		// if err != nil {
		// 	fmt.Println("failed to decode jwt token", err)
		// 	w.WriteHeader(http.StatusUnauthorized)
		// 	w.Write([]byte("Unauthorized."))
		// 	return
		// }
		// fmt.Println("token %+v", claims)

		ctx := context.WithValue(r.Context(), "userid", token.UID)

		handler(w, r.WithContext(ctx))
	}

	return wrappedHandler
}

func main() {
	log.Print("starting web services")

	app := &web.AppSvc{}

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
	admin, err := firebaseAdmin.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
		return
	}

	appCheck, err = admin.AppCheck(context.Background())
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
		return
	}

	// Create a Firebase auth client instance
	authClient, err = admin.Auth(context.Background())
	if err != nil {
		log.Fatalf("Failed to create Firebase auth client: %v", err)
		return
	}

	app.AuthClient = authClient

	r := mux.NewRouter()

	// r.HandleFunc("/user", requireAppCheck(app.UserCreateHandler)).Methods(http.MethodPost)
	// r.HandleFunc("/user", requireAppCheck(app.UserUpdateHandler)).Methods(http.MethodPut)
	r.HandleFunc("/user", requireAppCheck(app.UserFetchHandler)).Methods(http.MethodGet)
	// r.HandleFunc("/user", requireAppCheck(app.UserDeleteHandler)).Methods(http.MethodDelete)

	r.HandleFunc("/register", app.UserRegistration).Methods(http.MethodPost)
	r.HandleFunc("/login", app.UserLogin).Methods(http.MethodPost)

	r.HandleFunc("/user", app.UserUpdateHandler).Methods(http.MethodPut)
	// r.HandleFunc("/user", app.UserFetchHandler).Methods(http.MethodGet)
	r.HandleFunc("/user", app.UserDeleteHandler).Methods(http.MethodDelete)

	r.HandleFunc("/file", app.FileListHandler).Methods(http.MethodGet)
	r.HandleFunc("/file", app.FileCreateHandler).Methods(http.MethodPost)
	r.HandleFunc("/file", app.UserUpdateHandler).Methods(http.MethodPut)
	r.HandleFunc("/file", app.UserFetchHandler).Methods(http.MethodGet)
	r.HandleFunc("/file", app.UserDeleteHandler).Methods(http.MethodDelete)

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
