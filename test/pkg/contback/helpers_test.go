package contback

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestCleanupBackendProcess(t *testing.T) {
	separator := slices.Index(os.Args, "--")
	if separator < 0 || os.Getenv("CLEANUP_HELPER_BINARY") == "" {
		return
	}
	args := os.Args[separator+1:]
	if len(args) == 0 {
		os.Exit(43)
	}
	output, err := os.ReadFile(os.Getenv("CLEANUP_INVENTORY"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(44)
	}
	switch args[0] {
	case "images":
		if !slices.Contains(args, "reference=werf-test-one") {
			os.Exit(45)
		}
		for _, arg := range args {
			if strings.HasPrefix(arg, "label=") {
				os.Exit(46)
			}
		}
		fmt.Print(string(output))
	case "image":
		images, err := parseDockerCleanupImages(output)
		if err != nil {
			os.Exit(47)
		}
		var names, digests []string
		found := false
		for _, image := range images {
			if image.ID != args[2] {
				continue
			}
			found = true
			for _, name := range image.Names {
				if strings.Contains(name, "@") {
					digests = append(digests, name)
				} else {
					names = append(names, name)
				}
			}
		}
		if !found {
			fmt.Fprintln(os.Stderr, "No such image: "+args[2])
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"Id": args[2], "RepoTags": names, "RepoDigests": digests, "Config": map[string]any{"Labels": map[string]string{"werf": "werf-test-one"}}}); err != nil {
			os.Exit(48)
		}
	case "rmi":
		if len(args) != 3 || args[1] != "--no-prune" {
			os.Exit(53)
		}
		ref := args[len(args)-1]
		calls, err := os.OpenFile(os.Getenv("CLEANUP_CALLS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			os.Exit(49)
		}
		if _, err := fmt.Fprintln(calls, ref); err != nil {
			os.Exit(50)
		}
		if err := calls.Close(); err != nil {
			os.Exit(51)
		}
		if os.Getenv("CLEANUP_FAIL") == "1" {
			os.Exit(42)
		}
		if os.Getenv("CLEANUP_NOOP") != "1" {
			if err := os.WriteFile(os.Getenv("CLEANUP_INVENTORY"), []byte(os.Getenv("CLEANUP_REMAINING")), 0o600); err != nil {
				os.Exit(52)
			}
		}
	default:
		os.Exit(43)
	}
	os.Exit(0)
}
