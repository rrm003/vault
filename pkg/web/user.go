package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	PrimaryEmail   string    `json:"primary_email"`
	SecondaryEmail string    `json:"secondary_email"`
	PhotoURL       string    `json:"photo_url"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	AuthID         string    `json:"-"`
	Password       string    `json:"-"`
}

type UpdateReq struct {
	Name           string
	PrimaryEmail   string
	SecondaryEmail string
	PhotoURL       string
}

type UpdateResp struct {
	ID             uuid.UUID
	Name           string
	PrimaryEmail   string
	SecondaryEmail string
	PhotoURL       string
}

type UserRegistration struct {
	Name         string `json:"name"`
	PrimaryEmail string `json:"primary_email"`
	Password     string `json:"password"`
}

type UserLogin struct {
	Email    string `json:"primary_email"`
	Password string `json:"password"`
}

type UserLoginResponse struct {
	Token string `json:"token"`
}

func (app *AppSvc) UserRegistration(w http.ResponseWriter, r *http.Request) {
	log.Println("user : create request received")

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("error reading request body", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	// check user is already present
	user := &UserRegistration{}
	err = json.Unmarshal(reqBody, user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	fmt.Printf("user : after marshal : %+v\n", user)

	dbUser := &User{}
	_, err = app.DB.Query(dbUser, "select * from users where primary_email = ?", user.PrimaryEmail)
	if err != nil {
		fmt.Println("error reading db", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	fmt.Printf("dbuser : after query : %+v\n", dbUser)

	if dbUser.PrimaryEmail != "" {
		fmt.Println("user already exists")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("user already exists"))

		return
	}

	// Generate a UUID for the new user
	uid := uuid.New().String()

	// Generate a hash of the user's password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("failed to hash password: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Println("hashed password : ", string(hashedPassword))

	fmt.Println("Registration UID generated  : ", uid)
	// Create a new user in the database
	if _, err = app.DB.Exec("INSERT INTO users (id, name, primary_email, password) VALUES (?, ?, ?, ?)", uid, user.Name, user.PrimaryEmail, string(hashedPassword)); err != nil {
		log.Printf("failed to insert user into database: %v", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	// Register the new user and get a custom token for the user
	customToken, err := app.AuthClient.CustomToken(context.Background(), uid)
	if err != nil {
		log.Printf("failed to create custom token for user: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Println("successfully generated custom token ", customToken)

	resp := UserLoginResponse{Token: customToken}
	rawresp, err := json.Marshal(resp)
	if err != nil {
		log.Printf("failed to marshal response", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	fmt.Println("token generated")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(rawresp)
}

func (app *AppSvc) UserLogin(w http.ResponseWriter, r *http.Request) {
	log.Println("user : login received")

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("error reading request body", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	// check user is already present
	user := &UserLogin{}
	err = json.Unmarshal(reqBody, user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	fmt.Printf("user : after marshal : %+v\n", user)

	dbUser := &User{}
	_, err = app.DB.Query(dbUser, "select * from users where primary_email = ?", user.Email)
	if err != nil {
		fmt.Println("error reading db", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	fmt.Println("hashed password ", dbUser.Password)

	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password)); err != nil {
		fmt.Println("incorrect password", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect password"))

		return
	}

	fmt.Println("user validation success")

	// Generate a Firebase custom token for the user
	// Register the new user and get a custom token for the user
	fmt.Println("login UID generated  : ", dbUser.ID.String())

	customToken, err := app.AuthClient.CustomToken(context.Background(), dbUser.ID.String())
	if err != nil {
		log.Printf("failed to create custom token for user: %v", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	resp := UserLoginResponse{Token: customToken}
	rawresp, err := json.Marshal(resp)
	if err != nil {
		log.Printf("failed to marshal response", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	fmt.Println("token generated")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(rawresp)
}

func (app *AppSvc) UserUpdateHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("user : update request received")

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("error reading request body", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	fmt.Println(data)
	w.WriteHeader(http.StatusOK)
}

func (app *AppSvc) UserFetchHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("user : fetch request received")

	userUID, ok := r.Context().Value("userid").(string)
	if !ok {
		// Handle the case where userUID is not available in the context
		http.Error(w, "User ID not found", http.StatusUnauthorized)
		return
	}

	_, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("error reading request body", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	user := &User{}
	fmt.Println("DB instance : ", app.DB)
	_, err = app.DB.Query(user, "select * from users where id = ?", userUID)
	if err != nil {
		fmt.Println("error reading db", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	fmt.Println("user :", user)

	resp, err := json.Marshal(user)
	if err != nil {
		fmt.Println("error encoding response", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, string(resp))
}

func (app *AppSvc) UserDeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("user : delete request received")

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("error reading request body", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	fmt.Println(data)
	w.WriteHeader(http.StatusOK)
}
