## Rapid7 InsightAppSec Threadfix Integration
This integration is a Golang based utility used for extracting, transforming, and pushing 
[Rapid7 InsightAppSec](https://www.rapid7.com/products/insightappsec/) Dynamic Application Security scan data into 
[Threadfix](https://threadfix.it/) for correlation of scan results between multiple application security tools.

If you are already an end user of InsightAppSec and Threadfix, releases for this integration can be found 
[here](https://github.com/rapid7/insightappsec-threadfix/releases) and `Getting Started` documentation is available 
[here](help.md).
 
Key features include:
* Imports InsightAppSec scan data into Threadfix
* Provides simple command line interface (CLI) walkthrough for configuration
* Offers flexible configuration for effectively filtering InsightAppSec data

## Getting Started and Documentation

All documentation for end users to get started with the integration can be found [here](help.md). For more information
about InsightAppSec, please visit the [Product Page](https://www.rapid7.com/products/insightappsec/).

## Development Experience

If you would like to contribute to this project, you'll first need to install [Go](https://www.golang.org/) on your 
machine. Note: this utility was built with Go version 1.13.4 and will continue to be maintained with the latest version
of Go moving forward.

### Development Environment Setup
After downloading the proper Go package or using your preferred package management tool, ensure your 
[GOPATH](https://golang.org/doc/code.html#GOPATH) has been defined properly and that `$GOPATH/bin` is in your path:
```
export PATH=$PATH:$(go env GOPATH)/bin
```

This utility utilized Go modules and it is highly recommended to clone this repository outside of your GOPATH.

### Running from Command-line
Prior to starting, ensure `go run main.go configure` is run to setup the local configuration for the utility. It is also
manually configurable at `config/settings.yml`; however, use of the `configure` command will ensure API keys are 
encrypted for storage.

#### AdHoc Execution
Once configured, it is possible to initiate a onetime execution with the `adhoc` flag:
```
> go run main.go --adhoc
```

This will read the configurations as defined in `settings.yml` and process any scans that match the configurations. Once 
complete, the utility will stop until initiated again. The `adhoc` flag is very beneficial for one-off imports or during
development and testing.

#### Run Integration on a Schedule
In addition, it is possible to run the integration with an internal cron schedule. This can be accomplished by running 
the utility without any flags at all:
 ```
 > go run main.go
 ```

### Utility Options
All utility options can be listed with the use of the `--help` flag:
```
> go run main.go --help
This application is an integration between Rapid7 InsightAppSec and Threadfix. It automates the generation 
and formatting of findings from InsightAppSec scans and then imports them into Threadfix. Once imported, scans and
findings can be correlated with other application security feeds and searched within the Threadfix management 
platform

Usage:
  rapid7-insightappsec-threadfix [flags]
  rapid7-insightappsec-threadfix [command]

Available Commands:
  configure   Configure the Rapid7 InsightAppSec Threadfix integration
  help        Help about any command
  version     Version of integration

Flags:
  -a, --adhoc           Adhoc run of integration without the use of scheduling
      --config string   config file (default is ./config/settings.yaml)
  -h, --help            help for rapid7-insightappsec-threadfix

Use "rapid7-insightappsec-threadfix [command] --help" for more information about a command.
```

## Building Integration Binary

This project uses Goreleaser - a build and release utility for Golang modules - for building and packaging it for 
use. It uses `.goreleaser.yml` configuration file to dictate the build and release options when compiling a Golang 
application. To use you must first [install goreleaser](https://goreleaser.com/install/). This can be accomplished 
on macOS with:
```
> brew install goreleaser/tap/goreleaser
```

Once installed, the following command will compile and package the environment specific binary while skipping release to
Github or other repositories:
```
> goreleaser release --skip-publish
```

The generated artifacts will exist for 64-bit binaries for Windows and Linux in their respective directories:
```
> ls dist/ | grep 'insightappsec-threadfix'
insightappsec-threadfix_linux_amd64
insightappsec-threadfix_windows_amd64
rapid7-insightappsec-threadfix.exe_0.1.0_Windows_64-bit.zip
rapid7-insightappsec-threadfix_0.1.0_Linux_64-bit.tar.gz
```

### Github Action for Automated Release
To trigger the included GitHub Action as part of the project, simply create a tag following semver (eg. v1.0.0). Once 
the tag is created, the action will be triggered and the release with accompanying Windows and Linux packages will be 
attached as release artifacts.
