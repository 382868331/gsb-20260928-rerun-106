package main

import (
	"os"

	netforensics "netforensics"
)

func main() {
	data, err := netforensics.GoldenPCAP()
	if err != nil {
		panic(err)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		panic(err)
	}
}
