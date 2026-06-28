package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"blindvault/pkg/client"
	"blindvault/pkg/crypto"
)

// unblindCmd handles the "unblind" command, which allows a user to unblind a blind signature using a request ID. It takes the following flags:
// --signature: hex-encoded blind signature (required)
// --id: request ID from `bv blind` (required)
// --dst: domain separation tag (default: "BCIS-V1-MESSAGE")
// --server: BlindVault server URL (default: "http://localhost:8080")
func unblindCmd() {
	fs := flag.NewFlagSet("unblind", flag.ExitOnError)
	var (
		sigHex    = fs.String("signature", "", "hex-encoded blind signature")
		requestID = fs.String("id", "", "request ID from `bv blind`")
		dst       = fs.String("dst", "BCIS-V1-MESSAGE", "domain separation tag")
		url       = fs.String("server", "http://localhost:8080", "BlindVault server URL")
	)
	err := fs.Parse(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Unable to parse inputs")
		fs.Usage()
		os.Exit(1)
	}
	if *sigHex == "" || *requestID == "" {
		fmt.Fprintln(os.Stderr, "Error: --signature and --id are required")
		fs.Usage()
		os.Exit(1)
	}
	cli, err := client.NewClient(&client.Config{
		ServerURL: *url,
		DST:       []byte(*dst),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	sigBytes, err := hex.DecodeString(*sigHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid signature hex: %v\n", err)
		os.Exit(1)
	}
	sigPoint, err := crypto.DeserializeG1(sigBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid signature point: %v\n", err)
		os.Exit(1)
	}
	unblinded, err := cli.Unblind(*requestID, sigPoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Unblinded signature:", hex.EncodeToString(unblinded.Compress()))
}
