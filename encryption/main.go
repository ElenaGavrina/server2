package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func encodingString(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}

	data, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	var TextRequest struct {
		Text string `json:"text"`
		Key  string `json:"key"`
	}

	err := json.Unmarshal(data, &TextRequest)
	if err != nil {
		log.Printf("Error happened in JSON unmarshal. Err: %s", err)
	}

	enc, err := EncryptMessage(TextRequest.Text, []byte(TextRequest.Key))
	if err != nil {
		log.Printf("could not encrypt: %v",err)
	}

	res, err := json.Marshal(enc)
	if err != nil {
		log.Printf("Error happened in JSON marshal. Err: %s", err)
	}

	fmt.Println(string(res))

}

func decodingString(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}

	data, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	var CipherRequest struct {
		Cipher string `json:"cipher"`
		Key    string `json:"key"`
	}

	err := json.Unmarshal(data, &CipherRequest)
	if err != nil {
		log.Printf("Error happened in JSON unmarshal. Err: %s", err)
	}

	dec, err := DecryptMessage(CipherRequest.Cipher, []byte(CipherRequest.Key))
	if err != nil {
		log.Printf("%v", err.Error())
	}

	res, err := json.Marshal(dec)
	if err != nil {
		log.Printf("Error happened in JSON marshal. Err: %s", err)
	}

	fmt.Println(string(res))

}

func encodingFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}

	r.ParseMultipartForm(10 << 20)
	multForm := r.MultipartForm
	for key := range multForm.File {
		file, _, err := r.FormFile(key)
		if err != nil {
			fmt.Println("Error Retrieving the File")
			fmt.Println(err)
			return
		}
	
		defer file.Close()

		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println(err)
		}

		err = checkingFileFormat(w, fileBytes)
		if err != nil{
			return 
		}
		
		eKey := multForm.Value["key"][0]
		
		enc, err := EncryptMessage(string(fileBytes), []byte(eKey))

		tempFile, err := ioutil.TempFile("enc-file", "*.txt")
		if err != nil {
			fmt.Println(err)
		}
		defer tempFile.Close()
		tempFile.Write([]byte(enc))

	}
	
}

func decodingFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}

	r.ParseMultipartForm(10 << 20)
	multForm := r.MultipartForm
	for key := range multForm.File {
		file, _, err := r.FormFile(key)
		if err != nil {
			fmt.Println("Error Retrieving the File")
			fmt.Println(err)
			return
		}
		defer file.Close()

		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println(err)
		}

		err =checkingFileFormat(w, fileBytes)
		if err != nil{
			return 
		}

		dKey := multForm.Value["key"][0]

		dec, err := DecryptMessage(string(fileBytes), []byte(dKey))

		tempFile, err := ioutil.TempFile("dec-file", "decrypt-*.txt")
		if err != nil {
			fmt.Println(err)
		}
		defer tempFile.Close()
		tempFile.Write([]byte(dec))
	}

}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/es", encodingString)
	mux.HandleFunc("/ds", decodingString)
	mux.HandleFunc("/ef", encodingFile)
	mux.HandleFunc("/df", decodingFile)
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}

}

func EncryptMessage(message string, key []byte) (string, error) {
	byteMsg := []byte(message)
	block, err := aes.NewCipher(key)
	//изменила внутряк, чтобы прога не падала
	if err != nil {
		return "could not create new cipher", err
	}
	//fmt.Println("could not create new cipher")
	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "could not encrypt",err
	}
	//return errors.New(fmt.Sprintf("No folders found by path: %v", err), nil

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func DecryptMessage(message string, key []byte) (string, error) {

	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "could not base64 decode", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "could not create new cipher", err
	}

	if len(cipherText) < aes.BlockSize {
		return "invalid ciphertext block size", err
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

func checkingFileFormat(w http.ResponseWriter, data []byte) error{
	filetype := http.DetectContentType(data)
	if filetype != "text/plain; charset=utf-8" {
		http.Error(w, "The provided file format is not allowed. Please upload a txt file", http.StatusBadRequest)
		return errors.New("This file can't be encrypted")
	}
	return nil
}




//сделать бота
//поискать варианты проектов для GO
//деплоинг бота на HEROKU


