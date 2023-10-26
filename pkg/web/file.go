package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rrm003/valut/pkg/gcp"
)

func (app *AppSvc) FileCreateHandler(w http.ResponseWriter, r *http.Request) {
	file, handler, err := r.FormFile("file")
	// fileName := r.FormValue("file_name")
	if err != nil {
		fmt.Println("file create", "failed to read file", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer file.Close()

	storageSvc, err := gcp.GetStorageSvc()
	if err != nil {
		fmt.Println("file create", "failed to get storage svc", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = gcp.CreateFile(storageSvc, "rrm/", handler.Filename, file)
	if err != nil {
		fmt.Println("file create", "failed to store file in bucket", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (app *AppSvc) FileListHandler(w http.ResponseWriter, r *http.Request) {
	storageSvc, err := gcp.GetStorageSvc()
	if err != nil {
		fmt.Println("file create", "failed to get storage svc", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	list, err := gcp.ListObjects(storageSvc)
	if err != nil {
		fmt.Println("file create", "failed to store file in bucket", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
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
