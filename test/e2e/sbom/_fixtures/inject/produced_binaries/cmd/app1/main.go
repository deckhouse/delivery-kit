package main

import "github.com/spf13/cobra"

func main() {
	cmd := &cobra.Command{Use: "app1"}
	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}
