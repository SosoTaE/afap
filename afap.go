package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
)

const (
	maxChunkSize = 245
)

func main() {

	if len(os.Args) != 3 {
		fmt.Println("Usage: afap  <server-address> <file-path>")
		fmt.Println("Example: afap localhost:8080 ./myfile.txt")
		os.Exit(1)
	}

	serverAddr := os.Args[1]
	filePath := os.Args[2]

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Fatalf("File does not exist: %s", filePath)
	}

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	fmt.Printf("Connected to server at %s\n", serverAddr)

	pubKeyBuf := make([]byte, 512)
	n, err := conn.Read(pubKeyBuf)
	if err != nil {
		log.Fatalf("Failed to read server's public key: %v", err)
	}

	fmt.Println(string(pubKeyBuf[:n]))

	// Parse server's public key
	block, _ := pem.Decode(pubKeyBuf[:n])
	if block == nil {
		log.Fatalf("Failed to decode server's public key")
	}

	serverPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse server's public key: %v", err)
	}

	rsaKey, ok := serverPubKey.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("Server's key is not an RSA public key")
	}

	fmt.Println("Received server's public key")

	fileName := filepath.Base(filePath)

	encryptedFileName, err := rsa.EncryptPKCS1v15(rand.Reader, rsaKey, []byte(fileName))

	if err != nil {
		log.Fatalf("Failed to encrypt file name: %v", err)
	}

	_, err = conn.Write(encryptedFileName)
	if err != nil {
		log.Fatalf("Failed to send file name: %v", err)
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	// Get file size for progress reporting
	fileInfo, err := file.Stat()
	if err != nil {
		log.Fatalf("Failed to get file info: %v", err)
	}
	fileSize := fileInfo.Size()

	// Buffer for reading chunks
	buffer := make([]byte, maxChunkSize)
	totalSent := 0

	// Read and encrypt file in chunks
	for {
		n, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("Error reading file: %v", err)
		}

		if n == 0 {
			break
		}

		// Encrypt chunk with server's public key
		encryptedChunk, err := rsa.EncryptPKCS1v15(rand.Reader, rsaKey, buffer[:n])
		if err != nil {
			log.Fatalf("Failed to encrypt chunk: %v", err)
		}

		// Send encrypted chunk
		_, err = conn.Write(encryptedChunk)
		if err != nil {
			log.Fatalf("Failed to send encrypted chunk: %v", err)
		}

		totalSent += n

		// Print progress
		progress := float64(totalSent) / float64(fileSize) * 100
		fmt.Printf("\rSending: %.1f%% complete (%d/%d bytes)", progress, totalSent, fileSize)
	}

	fmt.Printf("\nFile sent successfully: %s (%d bytes)\n", fileName, totalSent)

	// Wait for confirmation from server
	responseBuf := make([]byte, 512)
	n, err = conn.Read(responseBuf)
	if err != nil {
		log.Printf("Warning: Could not read server confirmation: %v", err)
	} else {
		fmt.Printf("Server response: %s\n", string(responseBuf[:n]))
	}

	conn.Close()
}
