package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/rawbytedev/blindvault/pkg/client"
	"github.com/rawbytedev/blindvault/pkg/crypto"
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
	b, err := hex.DecodeString(*blinded)
	must(err, "Error: invalid blinded hex")
	sigB, err := hex.DecodeString(*sig)
	must(err, "Error: invalid Signature hex")
	pkB, err := hex.DecodeString(*pk)
	must(err, "Error: invalid Public Key hex")
	r1B, err := hex.DecodeString(*r1)
	must(err, "Error: invalid R1 hex")
	r2B, err := hex.DecodeString(*r2)
	must(err, "Error: invalid R2 hex")
	sB, err := hex.DecodeString(*s)
	must(err, "Error: invalid S hex")
	cB, err := hex.DecodeString(*c)
	must(err, "Error: invalid C hex")
	blindedPoint, err := crypto.DeserializeG1(b)
	must(err, "Error: invalid blindedPoint")
	sigPoint, err := crypto.DeserializeG1(sigB)
	must(err, "Error: invalid signature point")
	pkPoint, err := crypto.DeserializeG2(pkB)
	must(err, "Error: invalid Public Key")
	r1Point, err := crypto.DeserializeG2(r1B)
	must(err, "Error: invalid R1 point")
	r2Point, err := crypto.DeserializeG1(r2B)
	must(err, "Error: invalid R2 point")
	sScalar, err := crypto.NewBlstScalarFromBytes(sB)
	must(err, "Error: invalid Scalar S")
	cScalar, err := crypto.NewBlstScalarFromBytes(cB)
	must(err, "Error: invalid Scalar C")
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

func must(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %v\n", msg, err)
		os.Exit(1)
	}
}
