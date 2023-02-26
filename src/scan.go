package main

import (
	"os"
	"sync"
	"fmt"
	"bytes"
	yara "github.com/hillu/go-yara/v4"

	. "github.com/jeromehadorn/scanner/def"
	. "github.com/jeromehadorn/scanner/config"
	. "github.com/jeromehadorn/scanner/filesystem"
	. "github.com/jeromehadorn/scanner/log"
)

func Scan(c Config, targetPath string, rules *yara.Rules) error {
	var scan_wg sync.WaitGroup
	filesToScan := make(chan string, c.Threads)

	var match_wg sync.WaitGroup
	matchesToProcess := make(chan ScanMatch)

	var fail_wg sync.WaitGroup
	failsToProcess := make(chan ScanFailure)

	// Collect Results
	scan_wg.Add(c.Threads)
	for i := 0; i < c.Threads; i++ {
		go ScanFiles(i, rules, &scan_wg, &filesToScan, &failsToProcess, &matchesToProcess, &match_wg, &fail_wg)
	}

	// Start Receiving Matches / Scan Failures
	var matches []ScanMatch
	var matchMU sync.Mutex

	var failures []ScanFailure
	var failMU sync.Mutex

	go CollectMatches(&matches, &match_wg, &matchesToProcess, &matchMU)
	go CollectScanFailures(&failures, &fail_wg, &failsToProcess, &failMU)

	// Load Files to fileScanStack
	filesystem := FileSystem{}
	if err := filesystem.Setup(c, targetPath); err != nil {
		ErrorLogger.Fatal(err)
	}
	if _, err := LoadFiles(targetPath, c, filesToScan, &filesystem); err != nil {
		return fmt.Errorf("Error walking filepath whilst gathering Target files. Err: %s", err)
	}

	close(filesToScan)
	scan_wg.Wait()

	close(matchesToProcess)
	match_wg.Wait()

	close(failsToProcess)
	fail_wg.Wait()

	if err := filesystem.Finish(); err != nil {
		ErrorLogger.Fatal(err)
	}

	ResultLogger.Printf("%d Match(es) found\n", len(matches))

	return nil
}

// Gather all target filepaths that should be scanned
func LoadFiles(TargetPath string, c Config,  fileScanStack chan<- string, f IFileSystem) ([]FileAccessIssue, error) {

	accessIssues := []FileAccessIssue{}

	walking := func(path string, file os.FileInfo, err error) error {
		if err != nil {
			// Note: "Access is denied" errors
			if file != nil {
				ErrorLogger.Printf("Walking File resulted in error: %s, %v", err, file.Mode())
			} else {
				ErrorLogger.Printf("Walking File resulted in error: %s", err)
			}

			issue := FileAccessIssue{
				Path: path,
				Err:  err,
			}
			accessIssues = append(accessIssues, issue)
			return nil
		}

		if file.Mode().IsRegular() && file.Size() > 0 {
			fileScanStack <- path
			return nil
		}
		return nil
	}

	issues, err := f.Walk(TargetPath, walking)
	accessIssues = append(accessIssues, issues...)
	return accessIssues, err
}

func CollectMatches(matches *[]ScanMatch, match_wg *sync.WaitGroup, matchesToProcess *chan ScanMatch, matchMU *sync.Mutex) {
	for m := range *matchesToProcess {
		go func(match ScanMatch) {
			(*matchMU).Lock()
			*matches = append(*matches, match)
			printMatch(match)
			(*matchMU).Unlock()
			defer match_wg.Done()
			}(m)
	}
}

func printMatch(match ScanMatch){
	ResultLogger.Printf("RULE  %s  MATCH on  %s", match.Rulename, match.File)
	ResultLogger.Printf("Rulefile: %s", match.Namespace)
	for _, ma := range match.MatchedStrings {
		var buf bytes.Buffer
		buf.WriteString("  ")
		buf.WriteString(ma.Name)
		buf.WriteString(": ")
		buf.WriteString(string(ma.Data))
		buf.WriteString(" (at ")
		buf.WriteString(fmt.Sprintf("%d", ma.Offset))
		buf.WriteString(")")
		ResultLogger.Println(buf.String())
	}
	ResultLogger.Println()
}


func CollectScanFailures(failures *[]ScanFailure, failure_wg *sync.WaitGroup, failsToProcess *chan ScanFailure, failMU *sync.Mutex) {
	for m := range *failsToProcess {
		go func(fail ScanFailure) {
			(*failMU).Lock()
			*failures = append((*failures), fail)
			(*failMU).Unlock()
			ErrorLogger.Printf("Error scanning file: %s, err: %s", fail.File, fail.Error)
			defer failure_wg.Done()
		}(m)
	}
}

func ScanFiles(tid int, rules *yara.Rules, wg *sync.WaitGroup, filesToScan *chan string, failsToProcess *chan ScanFailure, matchesToProcess *chan ScanMatch, match_wg *sync.WaitGroup, failure_wg *sync.WaitGroup) {
	scanner, err := yara.NewScanner(rules)
	if err != nil {
		ErrorLogger.Fatalf("Failed to create a new scanner. Thread: %d Error: %s", tid, err)
	}

	for filePath := range *filesToScan {
		var allMatches yara.MatchRules
		scanner.SetCallback(&allMatches)

		if err := scanner.ScanFile(filePath); err != nil {
			failure_wg.Add(1)
			*failsToProcess <- ScanFailure{
				File:  filePath,
				Error: err,
			}
		}

		for _, m := range allMatches {
			match_wg.Add(1)
			*matchesToProcess <- ScanMatch{
				File:           filePath,
				Rulename:       m.Rule,
				Namespace:      m.Namespace,
				Tags:           m.Tags,
				Metas:          m.Metas,
				MatchedStrings: m.Strings,
			}
		}

	}

	wg.Done()
}
