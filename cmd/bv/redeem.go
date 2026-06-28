package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"blindvault/pkg/client"
	"blindvault/pkg/crypto"
)

// redeemCmd handles the "redeem" command, which allows a user to redeem a credential using an unblinded signature and witness point. It takes the following flags:
// --signature: hex-encoded unblinded signature (required)
// --witness: hex-encoded witness point (required)
// --class: credential class (required)
// --epoch: key epoch (required)
// --dst: domain separation tag (default: "BCIS-V1-MESSAGE")
// --server: BlindVault server URL (default: "http://localhost:8080")
func redeemCmd() {
	fs := flag.NewFlagSet("redeem", flag.ExitOnError)
	var (
		sigHex     = fs.String("signature", "", "hex-encoded unblinded signature")
		witnessHex = fs.String("witness", "", "hex-encoded witness point")
		class      = fs.String("class", "", "credential class")
		epoch      = fs.String("epoch", "", "key epoch")
		dst        = fs.String("dst", "BCIS-V1-MESSAGE", "domain separation tag")
		url        = fs.String("server", "http://localhost:8080", "BlindVault server URL")
	)
	err := fs.Parse(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Unable to parse inputs")
		fs.Usage()
		os.Exit(1)
	}
	if *sigHex == "" || *witnessHex == "" || *class == "" || *epoch == "" {
		fmt.Fprintln(os.Stderr, "Error: --signature, --witness, --class, and --epoch are required")
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
	sigBytes, _ := hex.DecodeString(*sigHex)
	sigPoint, err := crypto.DeserializeG1(sigBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid signature: %v\n", err)
		os.Exit(1)
	}
	witBytes, _ := hex.DecodeString(*witnessHex)
	witPoint, err := crypto.DeserializeG1(witBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid witness: %v\n", err)
		os.Exit(1)
	}
	valid, err := cli.Redeem(sigPoint, witPoint, *class, *epoch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if valid {
		fmt.Println("Credential redeemed successfully")
	} else {
		fmt.Println("Credential is invalid or already consumed")
		os.Exit(1)
	}
}
