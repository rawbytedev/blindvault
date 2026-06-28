package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"blindvault/pkg/client"
)

func blindCmd() {
	fs := flag.NewFlagSet("blind", flag.ExitOnError)
	var (
		msg = fs.String("message", "", "message to blind")
		dst = fs.String("dst", "BCIS-V1-MESSAGE", "domain separation tag")
		url = fs.String("server", "http://localhost:8080", "BlindVault server URL")
	)
	err := fs.Parse(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Unable to parse inputs")
		fs.Usage()
		os.Exit(1)
	}
	if *msg == "" {
		fmt.Fprintln(os.Stderr, "Error: --message is required")
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
	result, err := cli.Blind([]byte(*msg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	out := struct {
		Blinded   string `json:"blinded"`
		Witness   string `json:"witness"`
		RequestID string `json:"request_id"`
	}{
		Blinded:   hex.EncodeToString(result.Blinded.Compress()),
		Witness:   hex.EncodeToString(result.Witness.Compress()),
		RequestID: result.RequestID,
	}
	err = json.NewEncoder(os.Stdout).Encode(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
