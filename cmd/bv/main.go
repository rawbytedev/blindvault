package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: bv <command> [options]")
		fmt.Println("Commands: blind, verify, unblind, redeem")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "blind":
		blindCmd()
	case "verify":
		verifyCmd()
	case "unblind":
		unblindCmd()
	case "redeem":
		redeemCmd()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
