package nativegate

import (
	"fmt"
)

// ImportCarries answers whether an import leaves a given file of its source image in the
// image that imports it. The answer rests on the directive alone - its add, to, include
// and exclude as the backend of the copy applies them - so it can be asked of a path
// before any snapshot of either image has been read.
//
// A path the copy does not carry is a path this image never received, and nothing a donor
// says about it is a statement about this image. Where the copy does carry it, the file
// lands under the destination of the directive by construction, so the question of where
// it landed is not asked here: what an import contributes is decided by what it carries.
//
// Only the lexical scope of the directive is read. A source path reached through a
// symlink, or a destination the stage turned into one, is a placement the directive alone
// cannot settle; those are the business of the gate, which holds both snapshots, and this
// answers for the file as the directive names it.
func ImportCarries(scope ImportScope, sourcePath string) (bool, error) {
	if scope.FromPath == "" || scope.ToPath == "" {
		return false, fmt.Errorf("no-data: the import scope carries no copy")
	}
	from := rootedImportPath(scope.FromPath)
	carries, err := importScopeCarries(scope, from)
	if err != nil {
		return false, err
	}
	file := rootedImportPath(sourcePath)
	// The import source is the file itself: the directive carries it or carries
	// nothing, and the filters of the copy are written against its own root.
	if file == from {
		return carries("."), nil
	}
	relative, under := pathUnder(from, file)
	if !under {
		return false, nil
	}

	return carries(relative), nil
}
