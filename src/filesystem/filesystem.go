// +build !windows

package filesystem

import (
	"fmt"

	"path/filepath"

	. "github.com/jeromehadorn/scanner/def"
	. "github.com/jeromehadorn/scanner/config"
)

type IFileSystem interface {
	Setup(c Config, root string) error
	Walk(root string, fn filepath.WalkFunc) ([]FileAccessIssue, error)
	Finish() error
}
type FileSystem struct{}

func (r *FileSystem) Setup(c Config, root string) error {
	return nil
}

func (r *FileSystem) Walk(root string, fn filepath.WalkFunc) ([]FileAccessIssue, error) {
	issues := []FileAccessIssue{}
	if root == "" {
		return issues, fmt.Errorf("no TargetPath/Root has been set. This is most likely linked to a failed VSS snapshot.")
	}
	return issues, filepath.Walk(root, fn)
}

func (r *FileSystem) Finish() error {
	return nil
}

