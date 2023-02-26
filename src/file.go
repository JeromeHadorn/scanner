package main

import (
	"errors"
	"os"
)

func ValidatePath(path string) error {
	isFile, _ := IsFile(path)
	isDir, _ := IsDir(path)
	isDrive, _ := IsDrive(path)

	if !(isFile || isDir || isDrive) {
		return errors.New("invalid path")
	}

	return nil
}

// Check if path is a file
func IsFile(path string) (bool, error) {
	_, err := os.Stat(path)

	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}

	return false, err
}

// Check if path is a directory
func IsDir(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	return fileInfo.IsDir(), nil
}

// Check if path is a drive
func IsDrive(path string) (bool, error) {
	if len(path) == 2 && path[1] == ':' {
		return true, nil
	}

	return false, nil
}
