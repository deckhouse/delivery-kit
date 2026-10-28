package main

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
)

func main() {
	fmt.Println(semver.MustParse("1.2.3").IncMinor().String())
}
