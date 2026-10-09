package main

import (
	"fmt"

	"example.com/mylib"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	kingpin.Parse()
	fmt.Println(mylib.Hello())
}
