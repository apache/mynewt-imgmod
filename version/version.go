package version

import "fmt"

var (
	Version   string = "unknown_version"
	BuildDate string = "unknown_date"
	GitState  string = "unknown_git_state"
)

func VersionStr() string {
	return fmt.Sprintf("%s / %s / %s", Version, GitState, BuildDate)
}
