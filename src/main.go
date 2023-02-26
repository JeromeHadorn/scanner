package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	. "github.com/jeromehadorn/scanner/config"
	. "github.com/jeromehadorn/scanner/log"
)



func init() {

	fmt.Println(`
	 _                                         _                    _ 
	| |                                       | |                  | |
	| |__   __ _ _ __ ___  _ __ ___   ___ _ __| |__   ___  __ _  __| |
	| '_ \ / _' | '_  '_ \| '_  '_ \ / _ \ '__| '_ \ / _ \/ _  |/ _  |
	| | | | (_| | | | | | | | | | | |  __/ |  | | | |  __/ (_| | (_| |
	|_| |_|\__,_|_| |_| |_|_| |_| |_|\___|_|  |_| |_|\___|\__,_|\__,_|
		
	`)
}

// Windows VSS flags
var (
	vss *bool
	vssSymLinkPath *string
	keepVSS *bool
	keepLink *bool
	force *bool
	timeout *int
)

func main() {
	rulesPath := flag.String("R", "", "YARA rules File or Directory")
	ruleVariables := flag.String("E", "", "YARA rule variables file path (.yml)")
	outputPath := flag.String("O", "", "Output Path (default: stdout)")
	logPath := flag.String("L", "", "Logging Path (default: stdout)")

	threads := flag.Int("t", 16, "Number of threads (for scanning)")

	strict := flag.Bool("s", false, "Strict mode")
	verbose := flag.Bool("v", false, "Verbose mode")
	debug := flag.Bool("d", false, "Debug mode")

	if runtime.GOOS == "windows" {
		// TODO: Add a tmp path if none is provided
		vss = flag.Bool("V", false, "VSS - Scan snapshot")
		vssSymLinkPath = flag.String("VSS", "", "VSS - Path create VSS symlink")
		keepVSS = flag.Bool("kV", false, "VSS - Keep snapshot")
		keepLink = flag.Bool("kL", false, "VSS - Keep symlink")
		force = flag.Bool("f", false, "VSS - Force snapshot creation. WARNING: can replace existing snapshots")
		timeout = flag.Int("T", 180, "VSS - Timeout for snapshot creation (min 180s)")
	}

	flag.Usage = usage
	flag.Parse()
	checkUsage(flag.NArg())

	// Validate Config
	c := Config{
		RulesPath:  *rulesPath,
		RuleVariables: *ruleVariables,
		OutputPath: *outputPath,
		LogPath:    *logPath,
		Threads:    *threads,
		Strict:     *strict,
		Verbose:    *verbose,
		Debug:      *debug,
		Targets:    flag.Args(),
		EnableVSS:  false,
		VSS:		 VSSConfig{},
	}

	if runtime.GOOS == "windows"  && *vss {
		c.EnableVSS = true
		c.VSS = VSSConfig{
			VSSSymLinkPath: *vssSymLinkPath,
			KeepVSS:        *keepVSS,
			KeepLink:       *keepLink,
			Force:          *force,
			Timeout:        *timeout,
		}
	}

	if err := Validate(c); err != nil {
		log.Fatal(err)
	}

	SetupLogger(*logPath, *outputPath)

	InfoLogger.Println(os.Args)

	// Compile Rules
	cmplr, err := CompileRules(c)
	if err != nil {
		ErrorLogger.Fatal(err)
	}
	rules, err := cmplr.GetRules()
	if err != nil {
		ErrorLogger.Fatal(err)
	}

	// Iterate over targets
	for _, arg := range flag.Args() {
		
		if err := ValidatePath(arg); err != nil {
			ErrorLogger.Println(err)
			if *strict {
				os.Exit(1)
			}
			continue
		}
		// Start Scan
		if err := Scan(c, arg, rules); err!= nil {
			ErrorLogger.Printf("ERROR: scanning %s, err: %s", *rulesPath, err)
			if *strict {
				os.Exit(1)
			}
			continue
		}
	}
}

func usage() {
	if runtime.GOOS == "windows" {
		fmt.Fprintf(os.Stderr, "usage:  scanner.exe [OPTIONS] [DIR|FILE|DRIVE...]\nScan files/directories/drives against YARA rules. Option to run a scan against a VSS snapshot.\n")
	} else {
		fmt.Fprintf(os.Stderr, "usage:  scanner [OPTIONS] [DIR|FILE...]\nScan files/directories against YARA rules.\n")
	}
	flag.PrintDefaults()
	os.Exit(1)
}

// Checks for unprocessed arguments passed to the application
func checkUsage(nargs int) {
	if nargs == 0 {
		fmt.Fprintln(os.Stderr, `Unexpected arguments. Please see below all accepted arguments and their default values.`)
		usage()
	}
}
