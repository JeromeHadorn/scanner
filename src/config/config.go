package config

type Config struct {
	RulesPath string
	RuleVariables string
	OutputPath string
	LogPath string

	Threads int

	Strict bool
	Verbose bool
	Debug bool

	Targets []string

	EnableVSS bool
	VSS VSSConfig
}

type VSSConfig struct {
	VSSSymLinkPath string
	KeepVSS bool
	KeepLink bool
	Force bool
	Timeout int
}

// TODO: Implement
func Validate(c Config) error{
	return nil
}