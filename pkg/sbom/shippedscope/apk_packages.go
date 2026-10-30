package shippedscope

import (
	"errors"
	"fmt"
	"strings"
)

// apkPackage is one entry of the database apk keeps of what it installed.
type apkPackage struct {
	Name    string
	Version string
	Arch    string
	Files   []string
	// Dirs are the directories apk made for it.
	Dirs []string
}

// parseAPKInstalled reads apk's installed database: one block per package, separated by a
// blank line, of "X:value" lines. P, V and A name the package; each F names a directory
// relative to the root and the R lines after it name the files apk put there.
//
// A block that names no package, or a file before any directory, is an error: the caller
// reads nothing of a database it cannot read whole, since a package skipped here would be
// taken for one the image does not have.
func parseAPKInstalled(body []byte) ([]apkPackage, error) {
	var packages []apkPackage
	var current apkPackage
	dir, started := "", false
	finish := func() error {
		if !started {
			return nil
		}
		if current.Name == "" || current.Version == "" {
			return errors.New("apk database entry names no package or version")
		}
		packages = append(packages, current)
		current, dir, started = apkPackage{}, "", false

		return nil
	}
	for number, line := range strings.Split(string(body), "\n") {
		if line == "" {
			if err := finish(); err != nil {
				return nil, err
			}

			continue
		}
		if len(line) < 2 || line[1] != ':' {
			return nil, fmt.Errorf("apk database line %d is not a field", number+1)
		}
		started = true
		value := line[2:]
		switch line[0] {
		case 'P':
			current.Name = value
		case 'V':
			current.Version = value
		case 'A':
			current.Arch = value
		case 'F':
			dir = "/" + strings.Trim(value, "/")
			current.Dirs = append(current.Dirs, dir)
		case 'R':
			if dir == "" {
				return nil, fmt.Errorf("apk database line %d names a file before its directory", number+1)
			}
			current.Files = append(current.Files, strings.TrimSuffix(dir, "/")+"/"+value)
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}

	return packages, nil
}
