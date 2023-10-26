package gcp

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

var (
	bucketName  = os.Getenv("BUCKET_NAME")
	projectID   = os.Getenv("PROJECT_ID")
	keyFilePath = os.Getenv("KEY_FILE_PATH")
)

type FileList struct {
	Name         []string  `json:"name"`
	Type         string    `json:"type"`
	ModifiedTime time.Time `json:"modified_time"`
	Size         int64     `json:"size"`
}

func GetStorageSvc() (*storage.BucketHandle, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)

		return nil, err
	}

	bucketName = "valut-bucket"
	bucket := client.Bucket(bucketName)

	return bucket, nil
}

func ListObjects(bucket *storage.BucketHandle) ([]*FileList, error) {
	fmt.Println("Objects in the bucket:")
	query := &storage.Query{Prefix: "rrm" + "/", Delimiter: ""}

	var names []*FileList
	it := bucket.Objects(context.Background(), query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("file attributes : %+v\n", attrs.Name)
		if attrs.Name[len(attrs.Name)-1] != '/' {
			path := strings.Split(attrs.Name, "/")
			names = append(names, &FileList{Name: path, Type: "file", ModifiedTime: attrs.Updated, Size: attrs.Size})
		} else {
			path := strings.Split(attrs.Name, "/")
			names = append(names, &FileList{Name: path, Type: "folder", ModifiedTime: attrs.Updated, Size: attrs.Size})
		}
	}

	return names, nil
}

func CreateFile(bucket *storage.BucketHandle, path, objectName string, file multipart.File) error {
	obj := bucket.Object(path + objectName)
	wc := obj.NewWriter(context.Background())

	if _, err := io.Copy(wc, file); err != nil {
		return fmt.Errorf("io.Copy: %v", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("Writer.Close: %v", err)
	}

	fmt.Printf("File %s created successfully.\n", objectName)
	return nil
}

func CreateFolder(bucket *storage.BucketHandle, folderName string) {
	obj := bucket.Object(folderName)
	w := obj.NewWriter(context.Background())
	if _, err := w.Write([]byte("")); err != nil {
		log.Fatalf("Failed to create folder: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Failed to close folder: %v", err)
	}
	fmt.Printf("Folder %s created successfully.\n", folderName)
}

func UpdateFile(bucket *storage.BucketHandle, objectName string, newContent []byte) {
	obj := bucket.Object(objectName)
	w := obj.NewWriter(context.Background())
	_, err := w.Write(newContent)
	if err != nil {
		log.Fatalf("Failed to update file: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Failed to close updated file: %v", err)
	}
	fmt.Printf("File %s updated successfully.\n", objectName)
}

func DeleteFile(bucket *storage.BucketHandle, objectName string) {
	obj := bucket.Object(objectName)
	if err := obj.Delete(context.Background()); err != nil {
		log.Fatalf("Failed to delete file: %v", err)
	}
	fmt.Printf("File %s deleted successfully.\n", objectName)
}

func DeleteFolder(bucket *storage.BucketHandle, folderName string) {
	query := &storage.Query{Prefix: folderName}

	it := bucket.Objects(context.Background(), query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if err := bucket.Object(attrs.Name).Delete(context.Background()); err != nil {
			log.Fatalf("Failed to delete object in the folder: %v", err)
		}
	}

	// Now, delete the folder itself
	obj := bucket.Object(folderName)
	if err := obj.Delete(context.Background()); err != nil {
		log.Fatalf("Failed to delete folder: %v", err)
	}
	fmt.Printf("Folder %s and its contents deleted successfully.\n", folderName)
}

func FetchFile(bucket *storage.BucketHandle, objectName string) {
	obj := bucket.Object(objectName)
	r, err := obj.NewReader(context.Background())
	if err != nil {
		log.Fatalf("Failed to fetch file: %v", err)
	}
	defer r.Close()
	content, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatalf("Failed to read file content: %v", err)
	}
	fmt.Printf("Fetched content from %s:\n%s\n", objectName, string(content))
}
