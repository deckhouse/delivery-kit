package main

import "github.com/spf13/cobra"

func main() {
	cmd := &cobra.Command{Use: "app"}
	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}
