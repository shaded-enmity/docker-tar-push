package main

import (
	"bytes"
	"fmt"
	trust "github.com/docker/libtrust"
	"io"
	"os"
)

func main() {
	if pk, err := trust.GenerateECP256PrivateKey(); err != nil {
		fmt.Printf("error generating private key: %s\n", err.Error())
	} else {
		if buf, err := pk.MarshalJSON(); err != nil {
			fmt.Printf("error marshalling private key: %s\n", err.Error())
		} else {
			io.Copy(os.Stdout, bytes.NewReader(buf))
		}
	}
}
