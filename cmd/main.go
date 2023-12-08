package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	sigChan = make(chan os.Signal, 1)
	conn    *tls.Conn
)

// ssl telnet client
func main() {
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go catchInterrupt()
	// Define the TLS configuration
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Dial a connection
	conn, err := tls.Dial("tcp", "www.watskebeurt.nl:443", conf)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}

	// Create a new reader for the standard input
	reader := bufio.NewReader(os.Stdin)

	for {
		// Read a line from the standard input
		fmt.Print("$ ")
		text, _ := reader.ReadString('\n')

		// Write the input text to the connection
		_, err = conn.Write([]byte(text))
		if err != nil {
			log.Fatalf("Failed to write to connection: %v", err)
		}

		// Read the response
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatalf("Failed to read: %v", err)
		}

		log.Printf("Received: %s", string(buf[:n]))
	}
}

func catchInterrupt() {
	<-sigChan
	fmt.Println("\nReceived an interrupt, closing connection...")

	// Close the connection
	if err := conn.Close(); err != nil {
		log.Fatalf("Failed to close connection: %v", err)
	}

	os.Exit(0)
}
