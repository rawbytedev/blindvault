package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"blindvault/pkg/client"
	"blindvault/pkg/crypto"
)

// verifyCmd handles the "verify" subcommand.
/* It takes the following flags:
--blinded: hex-encoded blinded point (required)
--signature: hex-encoded blind signature (required)
--public-key: hex-encoded public key (required)
--proof-r1: hex-encoded R1 (required)
--proof-r2: hex-encoded R2 (required)
--proof-s: hex-encoded S (required)
--proof-c: hex-encoded C (required)
--dst: domain separation tag (default: "BCIS-V1-MESSAGE")
--server: BlindVault server URL (default: "http://localhost:8080")*/
func verifyCmd() {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var (
		blinded = fs.String("blinded", "", "hex-encoded blinded point")
		sig     = fs.String("signature", "", "hex-encoded blind signature")
		pk      = fs.String("public-key", "", "hex-encoded public key")
		r1      = fs.String("proof-r1", "", "hex-encoded R1")
		r2      = fs.String("proof-r2", "", "hex-encoded R2")
		s       = fs.String("proof-s", "", "hex-encoded S")
		c       = fs.String("proof-c", "", "hex-encoded C")
		dst     = fs.String("dst", "BCIS-V1-MESSAGE", "domain separation tag")
		url     = fs.String("server", "http://localhost:8080", "BlindVault server URL")
	)
	err := fs.Parse(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Unable to parse inputs")
		fs.Usage()
		os.Exit(1)
	}
	if *blinded == "" || *sig == "" || *pk == "" || *r1 == "" || *r2 == "" || *s == "" || *c == "" {
		fmt.Fprintln(os.Stderr, "Error: all flags are required")
		fs.Usage()
		os.Exit(1)
	}
	// Decode all hex
	b, _ := hex.DecodeString(*blinded)
	sigB, _ := hex.DecodeString(*sig)
	pkB, _ := hex.DecodeString(*pk)
	r1B, _ := hex.DecodeString(*r1)
	r2B, _ := hex.DecodeString(*r2)
	sB, _ := hex.DecodeString(*s)
	cB, _ := hex.DecodeString(*c)

	blindedPoint, err := crypto.DeserializeG1(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid blinded point: %v\n", err)
		os.Exit(1)
	}
	sigPoint, err := crypto.DeserializeG1(sigB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid signature: %v\n", err)
		os.Exit(1)
	}
	pkPoint, err := crypto.DeserializeG2(pkB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid public key: %v\n", err)
		os.Exit(1)
	}
	r1Point, err := crypto.DeserializeG2(r1B)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid R1: %v\n", err)
		os.Exit(1)
	}
	r2Point, err := crypto.DeserializeG1(r2B)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid R2: %v\n", err)
		os.Exit(1)
	}
	sScalar, err := crypto.NewBlstScalarFromBytes(sB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid S: %v\n", err)
		os.Exit(1)
	}
	cScalar, err := crypto.NewBlstScalarFromBytes(cB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid C: %v\n", err)
		os.Exit(1)
	}
	proof := &crypto.DLEQProof{
		R1: r1Point,
		R2: r2Point,
		S:  sScalar,
		C:  cScalar,
	}
	cli, _ := client.NewClient(&client.Config{
		ServerURL: *url,
		DST:       []byte(*dst),
	})
	valid := cli.VerifyProof(proof, blindedPoint, sigPoint, pkPoint)
	if valid {
		fmt.Println("DLEQ proof is valid")
	} else {
		fmt.Println("DLEQ proof is invalid")
		os.Exit(1)
	}
}
