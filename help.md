# Description

The Rapid7 InsightAppSec Threadfix integration is a utility designed to import InsightAppSec scan data to Threadfix to 
effectively correlate scan results across multiple application security tools. The integration provides flexible 
configuration options that allow the user to filter scan data by application, scan configuration, and timeframe. Once 
scan data is imported into Threadfix, the scan results can be visualized and correlated with other security scanning
tools.

Getting started with the utility is as easy as downloading the integration package to a system with access to both the
InsightAppSec and Threadfix APIs. Once configured it is easy to begin importing InsightAppSec scan results into 
Threadfix for teams to use.

# Key Features

* Imports InsightAppSec scan data into Threadfix
* Provides simple command line interface (CLI) walkthrough for configuration
* Offers flexible configuration for effectively filtering InsightAppSec data

# Requirements

* Rapid7 Platform API Key
* Threadfix API key

# Documentation

## Setup

### Connection

Prior to installing and configuring the integration, it is important to have the necessary connection details to both
InsightAppSec and Threadfix for communicating to the respective APIs. These details will then be used when configuring 
the integration through the command-line configuration walkthrough.

For InsightAppSec, it is necessary to retrieve both the InsightAppSec region and generate a Rapid7 platform API key.

| Configuration Settings | Expected Value                                                                    | Additional Documentation                                                                                                                               |
|------------------------|-----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| InsightAppSec Region   | Region of organization's InsightAppSec instance                                   | [List of Supported Regions](https://insight.help.rapid7.com/docs/product-apis#section-supported-regions)                                               |
| InsightAppSec API Key  | Generated organization or user API key for interacting with the InsightAppSec API | [Steps to generate an API Key](https://insightappsec.help.rapid7.com/docs/get-started-with-the-insightappsec-api#section-generate-an-insight-api-key) |

Since Threadfix is an on-premise application, it will be necessary to collect both the hostname/IP and port for 
interacting with the Threadfix API. In addition, an API key must also be generated.

| Configuration Settings | Expected Value                                                                    | Additional Documentation                                                                                  |
|------------------------|-----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| Threadfix Host         | The hostname, IP, or FQDN for accessing the Threadfix API and web interface       |                                                                                                           |
| Threadfix Port         | The port used for accessing the Threadfix API and web interface (default: 8080)   |                                                                                                           |
| Threadfix API Key      | Generated organization or user API key for interacting with the InsightAppSec API | [Steps to generate an API Key](https://denimgroup.atlassian.net/wiki/spaces/TDOC/pages/22619214/API+Keys) |

Once all of these details have been collected, they will be used during the Installation and Initial Configuration of
 the integration.

## Technical Details

### Installation

As a command-line utility, the InsightAppSec Threadfix integration has been designed to be installed on a Windows or 
Linux filesystem. Once the package has been downloaded, move the respective binary and included settings.yml to the 
following location:

| Integration Binary                 | Operating System                           | Installation Location                            |
|------------------------------------|--------------------------------------------|--------------------------------------------------|
| rapid7-insightappsec-threadfix     | Linux Distributions (Ubuntu / CentOS)      | /opt/rapid7/insightappsec_threadfix/             |
| rapid7-insightappsec-threadfix.exe | Windows (Windows 8+, Windows Server 2012+) | C:\Program Files\Rapid7\insightappsec_threadfix\ |

### Configuration

For initial setup, it will be necessary to initiate from a command-line interface:

Linux-based configuration:
```
> cd /opt/rapid7/insightappsec_threadfix/
> ./rapid7-insightappsec-threadfix configure
```

Windows-based configuration:
```
> cd /d C:\Program Files\Rapid7\insightappsec_threadfix\
> rapid7-insightappsec-threadfix.exe configure
```

The configuration wizard will walk you through setting up connection details for InsightAppSec and Threadfix, 
defining export configurations, and allow the modification of severity mapping between the two products. Additional 
details and command-line examples can be found in the following sections.

#### Configuring Connections

As noted in the `Connections` section, the necessary connection details for InsightAppSec and Threadfix will need to be
provided. The API keys are encrypted at rest to avoid clear text credentials from being visible.
```
The integration between Rapid7 InsightAppSec and Threadfix has not yet been configured. Would you like to configure the integration now?
✔ Yes
The configuration will now ask for connection details for communicating with the InsightAppSec and Threadfix APIs. Passwords and API keys will be stored in an encrypted format on the filesystem.
What region is your InsightAppSec account? Example regions are: us, eu, ca, au, ap. A full list of supported region codes is documented here: https://insight.help.rapid7.com/docs/product-apis#section-supported-regionsus
What is your InsightAppSec API key?*******************
What is your Threadfix IP address or hostname?https://127.0.0.1
What is your Threadfix port?8443
What is your Threadfix API key?**************
```

#### Defining Export Configurations

An export configuration refers to the fields pertaining to the retrieval of InsightAppSec scan data and its import into 
Threadfix. These configurations drive which scans and findings should be imported to Threadfix from InsightAppSec.

| Field    | Description                  |
|----------|------------------------------|
| InsightAppSec application | The InsightAppSec application(s) that will be used to retrieve scan data for import into Threadfix. A regex can be used to match applications by name
| Scan config filter | The scan configurations that will be used to limit which scans' data is retrieved for import. A regex can be used to match scan configs by name
| Only import most recent scan? | Whether to only import the most recent scan's data
| Days back from initial import | If the user answers no to the above, then historical scan data will be imported from InsightAppSec. This field defines the number of days back worth of data to retrieve
| Configuration name | A unique name to give the export configuration. Helps in identifying it if later modification is needed
| Threadfix application | The Threadfix application where the InsightAppSec scan data will be imported
| Threadfix team | The Threadfix team where the above application resides
| Enabled | Whether this export configuration is enabled for usage in the integration

Example command-line prompts and answers for export configurations can be found below:
```
The configuration will now ask to define export configurations. These are used to determine which scans are exported from InsightAppSec to Threadfix.
✔ New Configuration
What InsightAppSec Applications are within scope? You may provide a regular expression to match Applications by name. This will determine which applications' scans will be imported into ThreadfixHackazon
Please define a Scan Config filter to limit the scans within scope. You may provide a regular expression to match Scan Configs by nameDefault
✔ Yes
Please provide a name for this configurationHackazon Import
✔ Based on InsightAppSec application name
Please provide the name of the Threadfix TeamHackazon
✔ Yes
Use the arrow keys to navigate: ↓ ↑ → ← 
? There are currently 1 export configurations defined. Select the configuration you would like to modify or define a new configuration: 
  ▸ Hackazon Import (Enabled)
    New Configuration
    Done
```

_NOTE: When configuring export configurations, it is also possible to disable them from running. This allows for 
configurations to be disabled without deleting them._

#### Severity Mappings

InsightAppSec and Threadfix both use severities when referring to a vulnerability's threat level. Because they are not 
one-to-one between the two tools, this integration includes an option for mapping of severities as needed. The following 
shows the default mappings which should work for most implementations; however, they are fully customizable during the 
provided command-line configuration.

| InsightAppSec | Threadfix |
|---------------|-----------|
| SAFE          | Info      |
| INFORMATIONAL | Low       | 
| LOW           | Medium    |
| MEDIUM        | High      |
| HIGH          | Critical  |

Example command-line prompts and answers for severity mappings can be found below:
```
? Would you like to review severity mappings between InsightAppSec and Threadfix? Default settings are recommended in most scenarios.: 
  ▸ Yes
    No
? Severity Mappings (InsightAppSec : Threadfix): 
  ▸ SAFE : Info
    INFORMATIONAL : Low
    LOW : Medium
    MEDIUM : High
↓   HIGH : Critical
```

### Running Integration

For running the utility, there are two approaches:
1. One-time run
2. Running as a service with an internal schedule

#### One-time Run

If initiating the integration manually, it is possible to pass the `--adhoc` flag to ensure it runs once and then 
completes. This is useful when performing initial configurating or in scenarios where a team wants to control the exact 
time imports occur.

```
> rapid7-insightappsec-threadfix.exe --adhoc
``` 

#### Internal Scheduling as a Service

If configured as a service, this integration is best run by utilizing the internal scheduler. The internal scheduler 
will process each export configuration on the configured interval. By default this is set to every five minutes. To run
with the internal scheduler, simply initiate the utility without any flags:
```
> rapid7-insightappsec-threadfix.exe
```

## Troubleshooting

### Imported scan results between InsightAppSec and Threadfix are slightly different
When viewing the vulnerabilities in InsightAppSec versus those imported into Threadfix, it's normal to see a slight 
discrepancy in their numbers. This is because there is not a one-to-one mapping of vulnerabilities across the two tools, 
and thus there may be some vulnerabilities that cannot be imported. This should only occur for a small number of 
vulnerabilities and should have little to no impact on correlation across application security tools.

# Version History

* 1.0.0 - Initial release of integration

# Links

## References

* [Threadfix API Documentation](https://denimgroup.atlassian.net/wiki/spaces/TDOC/pages/22842096/ThreadFix+API)
* [InsightAppSec API Documentation](https://help.rapid7.com/insightappsec/en-us/api/v1/docs.html)
