package main

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

func main() {
	data := map[string]string{"key": "value"}
	out, err := yaml.Marshal(data)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
