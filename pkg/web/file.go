package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/uuid"
	"github.com/rrm003/valut/pkg/gcp"
	"google.golang.org/api/iterator"
)

type FetchFileReq struct {
	Path string `json:"path"`
	OTP  string `json:"otp"`
}

type Version struct {
	ID        int64     `json:"id"`
	Size      float64   `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

type FetchFileResp struct {
	URL      string    `json:"url"`
	Versions []Version `json:"versions"`
}

type DeleteFileReq struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type CreateFolderReq struct {
	Path string `json:"path"`
}

type UserFileOTP struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	FilePath  string    `json:"file_path"`
	OTP       string    `json:"otp"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Define the character set for the alphanumeric code
const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func (app *AppSvc) FileCreateHandler(w http.ResponseWriter, r *http.Request) {
	userUID, ok := r.Context().Value("userid").(string)
	if !ok {
		// Handle the case where userUID is not available in the context
		http.Error(w, "User ID not found", http.StatusUnauthorized)
		return
	}

	userUID = fmt.Sprintf("%s/", userUID)
	file, handler, err := r.FormFile("file")
	if err != nil {
		fmt.Println("file create", "failed to read file", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	path := r.FormValue("path")
	fmt.Println("uploading file at", path)

	defer file.Close()

	if path == "" {
		path = userUID
	} else {
		path = userUID + path + "/"
	}

	err = gcp.CreateFile(app.StorageSvc, path, handler.Filename, file)
	if err != nil {
		fmt.Println("file create", "failed to store file in bucket", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (app *AppSvc) FileListHandler(w http.ResponseWriter, r *http.Request) {
	userUID, ok := r.Context().Value("userid").(string)
	if !ok {
		// Handle the case where userUID is not available in the context
		http.Error(w, "User ID not found", http.StatusUnauthorized)
		return
	}

	userUID = fmt.Sprintf("%s", userUID)
	fmt.Println("request headers", r.Header)
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("error reading request body", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	fmt.Println("received req body ", string(reqBody))
	req := &FetchFileReq{}
	err = json.Unmarshal(reqBody, req)
	if err != nil {
		fmt.Println("error unmarshalling request body", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Printf("request body : %+v", req)

	storageSvc, err := gcp.GetStorageSvc()
	if err != nil {
		fmt.Println("file create", "failed to get storage svc", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.Path == "" {
		req.Path = userUID
	} else {
		req.Path = userUID + "/" + req.Path
	}

	list, err := gcp.ListObjects(storageSvc, req.Path)
	if err != nil {
		fmt.Println("file create", "failed to store file in bucket", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if list == nil {
		list = []*gcp.FileList{}
	}

	resp, err := json.Marshal(list)
	if err != nil {
		fmt.Println("file create", "failed to marshal response", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, string(resp))
}

// Function to generate a random alphanumeric code of a given length
func generateRandomCode() string {
	rand.Seed(time.Now().UnixNano())
	code := make([]byte, 6)
	for i := range code {
		code[i] = charset[rand.Intn(len(charset))]
	}
	return string(code)
}

func (app *AppSvc) FetchFileOTPHandler(w http.ResponseWriter, r *http.Request) {
	userUID, ok := r.Context().Value("userid").(string)
	if !ok {
		// Handle the case where userUID is not available in the context
		http.Error(w, "User ID not found", http.StatusUnauthorized)
		return
	}
	// userUID := "8bd67aed-6ec5-48a4-a6b6-73e794ca12d6"
	id := userUID

	fmt.Println("fetch file request", r)
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("error reading request body", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	body := &FetchFileReq{}
	err = json.Unmarshal(reqBody, body)
	if err != nil {
		fmt.Println("error unmarshalling request body", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Printf("req body %+v\n", body)

	body.Path = fmt.Sprintf("%s/%s", userUID, body.Path)

	opt := generateRandomCode()
	// create user file otp combination
	_, err = app.DB.Exec("insert into user_file_otp(user_id, file_path, otp, expires_at)  values(?, ?, ?, ?)", id, body.Path, opt, time.Now().Add(35*time.Second))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("no record found for combination of user = %s file %s otp %s \n", userUID, body.Path, body.OTP)
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		fmt.Println("error reading db", err)
		w.WriteHeader(http.StatusInternalServerError)

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

	e := &gcp.Event{
		Name:  "File access OTP",
		Email: user.PrimaryEmail,
		Msg:   fmt.Sprintf("OTP %s for file %s", opt, body.Path),
	}

	// send otp to email of user
	err = gcp.PublishMessage(app.Ctx, app.TopicOTP, e)
	if err != nil {
		fmt.Println("failed to publish msg", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.WriteHeader(http.StatusOK)
}

func (app *AppSvc) FetchFileHandler(w http.ResponseWriter, r *http.Request) {
	userUID, ok := r.Context().Value("userid").(string)
	if !ok {
		// Handle the case where userUID is not available in the context
		http.Error(w, "User ID not found", http.StatusUnauthorized)
		return
	}
	// userUID := "8bd67aed-6ec5-48a4-a6b6-73e794ca12d6"
	rawId := userUID
	userUID = fmt.Sprintf("%s/", userUID)

	fmt.Println("fetch file request", r)
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("error reading request body", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	body := &FetchFileReq{}
	err = json.Unmarshal(reqBody, body)
	if err != nil {
		fmt.Println("error unmarshalling request body", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Printf("req body %+v\n", body)

	body.Path = userUID + body.Path

	// validate user file otp combination
	ufotp := &UserFileOTP{}
	_, err = app.DB.Query(ufotp, "select * from user_file_otp where user_id = ? and file_path = ? and otp = ? and expires_at>=now()", rawId, body.Path, body.OTP)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Printf("no record found for combination of user = %s file %s otp %s \n", rawId, body.Path, body.OTP)
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		fmt.Println("error reading db", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	// path, err := gcp.FetchFile(app.StorageSvc, body.Path)
	// if err != nil {
	// 	fmt.Println("error fetching file", err)
	// 	w.WriteHeader(http.StatusInternalServerError)
	// 	return
	// }

	fmt.Println(body.Path)
	_, err = app.StorageSvc.Object(body.Path).Attrs(context.Background())
	if err != nil {
		log.Printf("Failed to get object attributes: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	opts := &storage.SignedURLOptions{
		Scheme:  storage.SigningSchemeV4,
		Method:  "GET",
		Expires: time.Now().Add(5 * time.Minute),
		QueryParameters: map[string][]string{
			"generation": {fmt.Sprintf("%d", 1700498282471719)},
		},
	}

	u, err := app.StorageSvc.SignedURL(body.Path, opts)
	if err != nil {
		fmt.Printf("Bucket(%q).SignedURL: %w \n", "valut-svc", err)
	}

	fmt.Println("signed url", u)

	resp := FetchFileResp{
		URL: u,
	}

	q := &storage.Query{
		Prefix:   body.Path,
		Versions: true,
	}

	versions := make([]Version, 0)
	// List all versions of the specified object
	it := app.StorageSvc.Objects(context.Background(), q)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			fmt.Printf("Error iterating through object versions: %v\n", err)
			return
		}

		versions = append(versions, Version{ID: attrs.Generation, Size: float64(attrs.Size), CreatedAt: attrs.Created})
		fmt.Printf("Object version: %v, Size: %v, Created: %v\n", attrs.Generation, attrs.Size, attrs.Created)
	}

	resp.Versions = versions

	rawResp, err := json.Marshal(resp)
	if err != nil {
		fmt.Println("error marshalling resp", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(rawResp)
}

func (app *AppSvc) FileDeleteHandler(w http.ResponseWriter, r *http.Request) {
	userUID, ok := r.Context().Value("userid").(string)
	if !ok {
		// Handle the case where userUID is not available in the context
		http.Error(w, "User ID not found", http.StatusUnauthorized)
		return
	}

	userUID = fmt.Sprintf("%s/", userUID)

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("error reading request body", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	req := &DeleteFileReq{}
	err = json.Unmarshal(reqBody, req)
	if err != nil {
		fmt.Println("error unmarshalling request body", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	req.Path = userUID + req.Path
	switch req.Type {
	case "file":
		err = gcp.DeleteFile(app.StorageSvc, req.Path)
		if err != nil {
			fmt.Println("failed to delete file :", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

	case "folder":
		err = gcp.DeleteFolder(app.StorageSvc, req.Path)
		if err != nil {
			fmt.Println("failed to delete folder :", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

	default:
		fmt.Println("unknown file type", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

func (app *AppSvc) CreateFolderHandler(w http.ResponseWriter, r *http.Request) {
	userUID, ok := r.Context().Value("userid").(string)
	if !ok {
		// Handle the case where userUID is not available in the context
		http.Error(w, "User ID not found", http.StatusUnauthorized)
		return
	}

	userUID = fmt.Sprintf("%s/", userUID)

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("error reading request body", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	req := &CreateFolderReq{}
	err = json.Unmarshal(reqBody, req)
	if err != nil {
		fmt.Println("error unmarshalling request body", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = gcp.CreateFolder(app.StorageSvc, userUID+req.Path)
	if err != nil {
		fmt.Println("error creating folder body", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Println("folder created")
}
