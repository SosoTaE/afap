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
	keySize    = 2048
	bufferSize = 256 // Size for encrypted chunks (must be <= RSA key size / 8)
)

func main() {
	// Start the server
	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()

	fmt.Println("Server started on :8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("New connection from: %s\n", clientAddr)

	// Generate a new RSA key pair for this connection
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Printf("Failed to generate key pair: %v", err)
		return
	}

	// Extract public key
	publicKey := &privateKey.PublicKey

	// Send public key to client
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Printf("Failed to marshal public key: %v", err)
		return
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	fmt.Println(string(pubKeyPEM))

	_, err = conn.Write(pubKeyPEM)
	if err != nil {
		log.Printf("Failed to send public key: %v", err)
		return
	}

	fileNameBuf := make([]byte, 256)
	n, err := conn.Read(fileNameBuf)
	if err != nil {
		log.Printf("Failed to read filename: %v", err)
		return
	}

	decryptedChunk, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, fileNameBuf[:n])

	if err != nil {
		log.Printf("Failed to decrypt file name: %v", err)
	}

	fileName := string(decryptedChunk)
	outputPath := filepath.Join("received", fileName)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0750); err != nil {
		log.Printf("Failed to create directory: %v", err)
		return
	}

	output, err := os.Create(outputPath)
	if err != nil {
		log.Printf("Failed to create output file: %v", err)
		return
	}
	defer output.Close()

	// Receive encrypted file chunks
	encryptedBuf := make([]byte, bufferSize)
	totalBytes := 0

	for {
		// Read encrypted chunk
		n, err := conn.Read(encryptedBuf)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading encrypted chunk: %v", err)
			return
		}

		if n == 0 {
			break
		}

		decryptedChunk, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedBuf[:n])
		if err != nil {
			log.Printf("Failed to decrypt chunk: %v", err)
			return
		}

		_, err = output.Write(decryptedChunk)
		if err != nil {
			log.Printf("Failed to write to file: %v", err)
			return
		}

		totalBytes += len(decryptedChunk)
	}

	fmt.Printf("Received and decrypted file '%s' from %s (%d bytes)\n", fileName, clientAddr, totalBytes)

	// Send confirmation
	conn.Write([]byte("File received successfully"))
}
