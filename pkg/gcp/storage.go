package gcp

import (
	"context"
	"fmt"
	"io"
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
	projectID   = "valut-svc" //os.Getenv("PROJECT_ID")
	keyFilePath = os.Getenv("KEY_FILE_PATH")
)

type FileList struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	ModifiedTime time.Time `json:"modified_time"`
	Size         int64     `json:"size"`
}

func GetStorageSvc() (*storage.BucketHandle, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Printf("Failed to create client: %v", err)

		return nil, err
	}

	// bucketName = "valut-bucket"
	bucketName = "valut-bucket-1"
	bucket := client.Bucket(bucketName)

	return bucket, nil
}

func GetProfileStorageSvc() (*storage.BucketHandle, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Printf("Failed to create client: %v", err)

		return nil, err
	}

	// bucketName = "vault-profile"
	bucketName = "vault-profile-1"
	bucket := client.Bucket(bucketName)

	return bucket, nil
}

func ListObjects(bucket *storage.BucketHandle, folderPath string) ([]*FileList, error) {
	fmt.Println("Objects in the bucket:", folderPath)
	query := &storage.Query{Prefix: folderPath + "/", Delimiter: "/"}

	var names []*FileList
	it := bucket.Objects(context.Background(), query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}

		if err != nil {
			log.Print(err)
		}

		fmt.Printf("file attributes : %+v\n", attrs.Name)

		atrrLen := len(attrs.Name)
		if atrrLen > 0 && attrs.Name[atrrLen-1] != '/' {
			path := strings.Split(attrs.Name, "/")
			names = append(names, &FileList{Name: path[len(path)-1], Type: "file", ModifiedTime: attrs.Updated, Size: attrs.Size})
		} else {
			prefix := strings.Split(attrs.Prefix, "/")
			fmt.Println(prefix, "len", len(prefix))
			if len(prefix) >= 2 {
				names = append(names, &FileList{Name: prefix[len(prefix)-2], Type: "folder", ModifiedTime: attrs.Updated, Size: attrs.Size})
			}
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

func CreateFolder(bucket *storage.BucketHandle, folderName string) error {
	fmt.Println("creating foldername", folderName)

	obj := bucket.Object(folderName + "/")

	w := obj.NewWriter(context.Background())
	if _, err := w.Write([]byte("")); err != nil {
		log.Printf("Failed to create folder: %v\n", err)
		return err
	}

	if err := w.Close(); err != nil {
		log.Printf("Failed to close folder: %v\n", err)
		return err
	}

	fmt.Printf("Folder %s created successfully.\n", folderName)
	return nil
}

func UpdateFile(bucket *storage.BucketHandle, objectName string, newContent []byte) {
	obj := bucket.Object(objectName)
	w := obj.NewWriter(context.Background())
	_, err := w.Write(newContent)
	if err != nil {
		log.Printf("Failed to update file: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Printf("Failed to close updated file: %v", err)
	}
	fmt.Printf("File %s updated successfully.\n", objectName)
}

func DeleteFile(bucket *storage.BucketHandle, objectName string) error {
	obj := bucket.Object(objectName)
	if err := obj.Delete(context.Background()); err != nil {
		log.Printf("Failed to delete file: %v", err)
		return err
	}

	fmt.Printf("File %s deleted successfully.\n", objectName)
	return nil
}

func DeleteFolder(bucket *storage.BucketHandle, folderName string) error {
	fmt.Println("deleting folder:", folderName)

	query := &storage.Query{Prefix: folderName}

	it := bucket.Objects(context.Background(), query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Print(err)
			return err
		}

		fmt.Println("files in folder ", attrs.Name)
		if err := bucket.Object(attrs.Name).Delete(context.Background()); err != nil {
			log.Println("Failed to delete object in the folder: %v", err)
			return err
		}
	}

	// Now, delete the folder itself
	// obj := bucket.Object(folderName)
	// if err := obj.Delete(context.Background()); err != nil {
	// 	log.Println("Failed to delete folder: %v", err)
	// 	return err
	// }
	fmt.Printf("Folder %s and its contents deleted successfully.\n", folderName)
	return nil
}

func FetchFile(bucket *storage.BucketHandle, objectName string) (string, error) {

	// accessID := "firebase-adminsdk-8r5g6@valut-svc.iam.gserviceaccount.com"
	// opts := &storage.SignedURLOptions{
	// 	Scheme:         storage.SigningSchemeV4,
	// 	GoogleAccessID: accessID,
	// 	Method:         "GET",                           // The HTTP method for the signed URL
	// 	Expires:        time.Now().Add(5 * time.Minute), // The expiration time for the URL
	// }

	// url, err := bucket.SignedURL(objectName, opts)
	// if err != nil {
	// 	log.Printf("failed to get signed url: %v", err)
	// 	return "", err
	// }
	// fmt.Println("signed url ", url)

	// obj := bucket.Object(objectName)
	// r, err := obj.NewReader(context.Background())
	// if err != nil {
	// 	log.Println("Failed to fetch file: %v", err)
	// }
	// defer r.Close()
	// content, err := ioutil.ReadAll(r)
	// if err != nil {
	// 	log.Println("Failed to read file content: %v", err)
	// }
	// fmt.Printf("Fetched content from %s:\n%s\n", objectName, string(content))

	return "", nil
}
