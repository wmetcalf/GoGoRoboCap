package main

import "fmt"

// These variables are set during build using -ldflags
var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

// versionInfo returns a formatted string containing version information
func versionInfo() string {
	return fmt.Sprintf("robocap version %s, commit %s, built at %s", 
		Version, Commit, BuildTime)
}
