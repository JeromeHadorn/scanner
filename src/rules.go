package main

import (
	"errors"
	"fmt"
	"os"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"path/filepath"
	"strings"

	yara "github.com/hillu/go-yara/v4"
	. "github.com/jeromehadorn/scanner/config"
	. "github.com/jeromehadorn/scanner/log"
)


// TODO: add recursive option
func CompileRules(c Config) (*yara.Compiler, error) {

	cmplr, err := yara.NewCompiler()
	if err != nil {
		return nil, errors.New("failed to create YARA compiler")
	}
	
	if c.RuleVariables != "" {
		if err := insertExternalVariables(cmplr, c.RuleVariables); err != nil {
			return nil, err
		}
	}

	err = filepath.Walk(c.RulesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error processing path: %s, err: %v", path, err)
		}

		// Skip Directories
		if info.IsDir() {
			return nil
		}

		if !strings.Contains(path, ".yar") {
			WarningLogger.Printf("SKIP non-YARA File '%s'\n", path)
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("can't open YARA rule file %s: %s", path, err)
		}

		if c.Verbose {
			InfoLogger.Printf("Processing rules from: %s\n", path)
		}

		err = cmplr.AddFile(f, path)
		defer f.Close()

		// Check Warnings & Errors
		for _, e := range cmplr.Errors {
			ErrorLogger.Printf("Parsing Error: %s - Line: %d  - %s\n\t", e.Filename, int(e.Line), e.Text)
		}

		for _, w := range cmplr.Warnings {
			if c.Verbose {
				WarningLogger.Printf("Rule Warning %s %d %s\n", w.Filename, int(w.Line), w.Text)
			}
		}

		if c.Verbose {
			InfoLogger.Printf("Finished processing rules from: %s with %d compiler errors & %d warnings\n", path, len(cmplr.Errors), len(cmplr.Warnings))
		}

		cmplr.Errors = nil
		cmplr.Warnings = nil
		return err
	})
	return cmplr, nil
}

func insertExternalVariables(cmp *yara.Compiler, variable string) error {
	type YamlConfig struct {
		variables map[string]interface{}
	}

	yamlFile, err := ioutil.ReadFile(variable)
    if err != nil {
        return err
    }

	yamlMap := make(map[string]interface{})
    err = yaml.Unmarshal(yamlFile, &yamlMap)
    if err != nil {
        return fmt.Errorf("Error parsing YAML file: %s\n", err)
    }

	for key, value := range yamlMap["variables"].(map[interface{}]interface{}) {
		if err := cmp.DefineVariable(key.(string), value); err != nil {
			return fmt.Errorf("defineVariable(): %s", err)
		}
	}
	return nil
}
