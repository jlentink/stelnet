package cmd

import (
	"bufio"
	"crypto/tls"
	"fmt"
	log "github.com/jlentink/yaglogger"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	sigChan = make(chan os.Signal, 1)
	conn    *tls.Conn
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "stelnet",
	Short: "Telnet for SSL connections",
	Long:  `stelnet is a telnet client that can connect to SSL connections. Yes you can also use: openssl s_client -connect <host>:port>`,
	Run:   run,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
	rootCmd.Flags().StringP("port", "p", "443", "Port to connect to")
	rootCmd.Flags().StringP("prompt", "P", "$", "What to indicate as the prompt")
	rootCmd.Flags().StringP("prompt-padding", "X", " ", "What should be used to pad the prompt")
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.Flags().BoolP("certificate", "c", false, "Show certificate information")
}

func catchInterrupt() {
	<-sigChan
	log.Print("\nReceived an interrupt, closing connection...\n")

	// Close the connection
	if conn == nil {
		os.Exit(0)
	}
	if err := conn.Close(); err != nil {
		log.Fatalf("Failed to close connection: %v", err)
	}

	os.Exit(0)
}

func showCertificate() {
	state := conn.ConnectionState()
	log.Printf("Version: %d\n", state.Version)
	log.Printf("HandshakeComplete: %t\n", state.HandshakeComplete)
	log.Printf("DidResume: %t\n", state.DidResume)
	log.Printf("CipherSuite: %d\n", state.CipherSuite)
	log.Printf("NegotiatedProtocol: %s\n", state.NegotiatedProtocol)
	log.Printf("ServerName: %s\n", state.ServerName)
	log.Printf("PeerCertificates: %d\n", len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		log.Printf("  Subject: %s\n", cert.Subject)
		log.Printf("  Issuer: %s\n", cert.Issuer)
		log.Printf("  SerialNumber: %s\n", cert.SerialNumber)
		log.Printf("  NotBefore: %s\n", cert.NotBefore)
		log.Printf("  NotAfter: %s\n", cert.NotAfter)
		log.Printf("  BasicConstraintsValid: %t\n", cert.BasicConstraintsValid)
		log.Printf("  IsCA: %t\n", cert.IsCA)
		log.Printf("  MaxPathLen: %d\n", cert.MaxPathLen)
		log.Printf("  MaxPathLenZero: %t\n", cert.MaxPathLenZero)
		log.Printf("  SubjectAlternateNames: %d\n", len(cert.DNSNames))
		for _, name := range cert.DNSNames {
			log.Printf("    %s\n", name)
		}
		log.Printf("  KeyUsage: %d\n", cert.KeyUsage)
		log.Printf("  ExtKeyUsage: %d\n", cert.ExtKeyUsage)
		log.Printf("  UnknownExtKeyUsage: %d\n", cert.UnknownExtKeyUsage)
		log.Printf("  OCSPServer: %d\n", len(cert.OCSPServer))
		for _, server := range cert.OCSPServer {
			log.Printf("    %s\n", server)
		}
	}
}

//func removeLine() {
//	log.Print("\033[1A\033[2K")
//}

func run(cmd *cobra.Command, args []string) {
	log.GetInstance().ShowLogLocation = false
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	port := cmd.Flag("port").Value.String()
	prompt := cmd.Flag("prompt").Value.String()
	padding := cmd.Flag("prompt-padding").Value.String()
	go catchInterrupt()

	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		log.Fatalf("Failed to get insecure flag: %v", err)
	}

	if len(args) < 1 {
		log.Fatalf("No host specified.")
	}
	host := args[0]

	if len(args) >= 2 {
		var err error
		_, err = strconv.Atoi(args[1])
		if err != nil {
			log.Fatalf("Invalid port specified.")
		}
		port = args[1]
	}

	// Define the TLS configuration
	conf := &tls.Config{
		InsecureSkipVerify: insecure,
	}

	log.Printf("Trying %s...", host)

	// Dial a connection
	conn, err = tls.Dial("tcp", fmt.Sprintf("%s:%s", host, port), conf)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}

	if cmd.Flag("certificate").Value.String() == "true" {
		showCertificate()
	}
	log.Printf("Connected to: %s(%s)", host, port)
	log.Printf("Escape character is '^c'.")

	// Create a new reader for the standard input
	reader := bufio.NewReader(os.Stdin)

	for {
		// Read a line from the standard input
		fmt.Print(prompt + padding)
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
			if err == io.EOF {
				log.Printf("Received EOF, closing connection...\n")
				break
			}
			log.Fatalf("Failed to read: %v", err)
		}

		log.Printf("Received: %s", string(buf[:n]))
	}

	if conn != nil {
		err := conn.Close()
		if err != nil {
			return
		}
	}
}
