
// +build windows

package filesystem

import (
	"path"
	"os"
	"fmt"
	"path/filepath"
	"io/ioutil"

	. "github.com/jeromehadorn/scanner/def"
	. "github.com/jeromehadorn/scanner/config"
	. "github.com/jeromehadorn/scanner/log"
	vss "github.com/jeromehadorn/vss"
)

type IFileSystem interface {
	Setup(c Config, root string) error
	Walk(root string, fn filepath.WalkFunc) ([]FileAccessIssue, error)
	Finish() error
}
type FileSystem struct {
	SnapshotRoot string
	SnapshotId string
	VSS VSSConfig
	EnableVSS bool
}

func (r *FileSystem) Setup(c Config, root string) error {
	r.VSS = c.VSS
	r.EnableVSS = c.EnableVSS

	if r.EnableVSS {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return fmt.Errorf("failed to get absolute path of root: %s", err)
		}

		drive, err := getDriveLetter(absRoot)
		if err != nil {
			return fmt.Errorf("failed to get drive letter of root: %s", err)
		}

		// Create VSS snapshot
		Snapshotter := vss.Snapshotter{}
		snapshot, err := Snapshotter.CreateSnapshot(drive, r.VSS.Timeout, r.VSS.Force)
		if err != nil {
			ErrorLogger.Fatal(err)
		}
		r.SnapshotId = snapshot.Id

		InfoLogger.Printf("Snapshot created: %s\n", snapshot.Id)

		// Symlink to snapshot
		if r.VSS.VSSSymLinkPath != "" {
			res, err := symlinkSnapshot(r.VSS.VSSSymLinkPath, snapshot.Id, snapshot.DeviceObjectPath)
			if err != nil {
				ErrorLogger.Fatal(err)
			}
			InfoLogger.Printf("Symlink created: %s\n", res)
		}

		r.SnapshotRoot = path.Join(r.VSS.VSSSymLinkPath, snapshot.Id, absRoot[3:])
	}
	return nil
}

func (r *FileSystem) Walk(root string, fn filepath.WalkFunc) ([]FileAccessIssue, error) {
	issues := []FileAccessIssue{}
	if root == "" {
		return issues, fmt.Errorf("no TargetPath/Root has been set. This is most likely linked to a failed VSS snapshot.")
	}

	if r.EnableVSS {
		r.SnapshotRoot = r.SnapshotRoot + "\\"
		InfoLogger.Println("Walking Snapshot: ", r.SnapshotRoot)
		if r.SnapshotRoot == "" {
			return issues, fmt.Errorf("No root path of snapshot given")
		}

		entries, err := ioutil.ReadDir(r.SnapshotRoot)
		if err != nil {
			issues = append(issues, FileAccessIssue{
				Path: r.SnapshotRoot,
				Err:  err,
			})
			return issues, fmt.Errorf("error occured reading contents of snapshot base directory, err: %s\n", err)
		}
		
		var abspath string
		abspath, err = filepath.Abs(r.SnapshotRoot)
		if err != nil {
			return issues, err
		}

		for _, entry := range entries {
			p := filepath.Join(abspath, entry.Name())
			if err := filepath.Walk(p, fn); err != nil {
				return issues, err
			}
		}
		return issues, nil
	}

	return issues, filepath.Walk(root, fn)
}

func (r *FileSystem) Finish() error {
	if !r.VSS.KeepVSS  && r.EnableVSS {
		Snapshotter := vss.Snapshotter{}
		err := Snapshotter.DeleteSnapshot(r.SnapshotId)
		if err != nil {
			return fmt.Errorf("failed to delete snapshot: %s, err: %s", r.SnapshotId, err)
		}
		InfoLogger.Printf("Snapshot deleted: %s\n", r.SnapshotId)
	}
	if !r.VSS.KeepLink  && r.EnableVSS {
		if err := os.RemoveAll(r.VSS.VSSSymLinkPath + "\\" + r.SnapshotId); err != nil {
			return fmt.Errorf("failed to delete symlink: %s, err: %s", r.VSS.VSSSymLinkPath + "\\" + r.SnapshotId, err)
		}
		InfoLogger.Printf("Symlink deleted: %s", r.VSS.VSSSymLinkPath + "\\" + r.SnapshotId)
	}
	return nil
}

func symlinkSnapshot(symlinkPath string, id string, deviceObjectPath string) (string, error) {
	snapshotSymLinkFolder := symlinkPath + "\\" + id + "\\"

	snapshotSymLinkFolder = filepath.Clean(snapshotSymLinkFolder)
	
	if err := os.MkdirAll(snapshotSymLinkFolder, 0700); err != nil {
		return "", fmt.Errorf("failed to create snapshot symlink folder for snapshot: %s, err: %s", id, err)
	}

	os.Remove(snapshotSymLinkFolder)
	InfoLogger.Printf("Symlink from: ", deviceObjectPath, " to: \n", snapshotSymLinkFolder)

	if err := os.Symlink(deviceObjectPath, snapshotSymLinkFolder); err != nil {
		return "", fmt.Errorf("failed to create symlink from: %s to: %s, error: %s", deviceObjectPath, snapshotSymLinkFolder, err)
	}

	return snapshotSymLinkFolder, nil
}


func getDriveLetter(path string) (string, error){
	if len(path) < 2 {
		return "", fmt.Errorf("Path too short")
	}
	// with drive letter
	c := path[0]
	if path[1] == ':' && path[2] == '\\' && 
		('0' <= c && c <= '9' || 'a' <= c && c <= 'z' ||
			'A' <= c && c <= 'Z') {
		return path[:3], nil
	}
	
	return "", fmt.Errorf("No drive letter found")
}