package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/manifoldco/promptui"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/components/threadfix"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"strconv"
	"strings"
)

var Configuration *SettingsConf
var messages Messages

const YES = "Yes"
const NO = "No"
const DONE = "Done"

type Messages struct {
	NotConfigured string
	Configured string
	ConnectionsConfig string
	ConfigurationsConfig string
	SeverityConfig string
}

func init() {
	messages = Messages{
		NotConfigured:        "The integration between Rapid7 InsightAppSec and Threadfix has not yet been configured. Would you like to configure the integration now?",
		Configured:           "The integration between Rapid7 InsightAppSec and Threadfix was previously configured. Would you like to review and edit the configurations?",
		ConnectionsConfig:    "The configuration will now ask for connection details for communicating with the InsightAppSec and Threadfix APIs. Passwords and API keys will be stored in an encrypted format on the filesystem.",
		ConfigurationsConfig: "The configuration will now ask to define export configurations. These are used to determine which scans are exported from InsightAppSec to Threadfix.",
		SeverityConfig:       "Would you like to review severity mappings between InsightAppSec and Threadfix? Default settings are recommended in most scenarios.",
	}
}

// check if configuration has been completed
func ConfigComplete() (bool, string) {
	emptyInsightAppSecConn :=  InsightAppSecConnection{}
	emptyThreadfixConn := ThreadfixConnection{}
	if Configuration.Connections.InsightAppSec == emptyInsightAppSecConn ||
		Configuration.Connections.Threadfix == emptyThreadfixConn ||
		len(Configuration.ExportConfigurations) == 0 {
		return false, messages.NotConfigured
	}
	return true, messages.Configured
}

func Configure(message string) (bool, *SettingsConf) {
	fmt.Println(message)

	cont, _ := PromptContinue()

	if cont == YES {
		// Set up Connections
		fmt.Println(messages.ConnectionsConfig)
		// InsightAppSec Connection
		region, _ := StringPrompt("What region is your InsightAppSec account? Example regions are: us, eu, ca, " +
			"au, ap. A full list of supported region codes is documented here: " +
			"https://insight.help.rapid7.com/docs/product-apis#section-supported-regions", false,
			Configuration.Connections.InsightAppSec.Region)
		Configuration.Connections.InsightAppSec.Region = region
		apiKey, _ := StringPrompt("What is your InsightAppSec API key?", true,
			shared.Decrypt(Configuration.Connections.InsightAppSec.Apikey))
		Configuration.Connections.InsightAppSec.Apikey = apiKey

		//Threadfix Connection
		host, _ := StringPrompt("What is your Threadfix IP address or hostname?", false,
			Configuration.Connections.Threadfix.Host)
		Configuration.Connections.Threadfix.Host = host
		port, _ := StringPrompt("What is your Threadfix port?", false,
			Configuration.Connections.Threadfix.Port)
		Configuration.Connections.Threadfix.Port = port
		apiKey, _ = StringPrompt("What is your Threadfix API key?", true,
			shared.Decrypt(Configuration.Connections.Threadfix.Apikey))
		Configuration.Connections.Threadfix.Apikey = apiKey

		// Set up Configurations
		fmt.Println(messages.ConfigurationsConfig)
		for {
			var prompt string
			var promptList []string
			if len(Configuration.ExportConfigurations) > 0 {
				prompt = fmt.Sprintf("There are currently %v export configurations defined. Select the "+
					"configuration you would like to modify or define a new configuration",
					len(Configuration.ExportConfigurations))

				for _, exportConfig := range Configuration.ExportConfigurations {
					var status string
					if exportConfig.Enabled {
						status = "Enabled"
					} else {
						status = "Disabled"
					}
					promptList = append(promptList, fmt.Sprintf("%s (%s)", exportConfig.Name, status))
				}
				promptList = append(promptList, []string{"New Configuration", DONE}...)
			} else {
				prompt = "There are no export configurations defined. Define a new configuration to get started."
				promptList = append(promptList, []string{"New Configuration", DONE}...)
			}

			resp, _ := PromptList(prompt, promptList)

			if resp == DONE {
				// Done with export configuration
				break
			} else if resp != "New Configuration" {
				// Update current configuration by pointer
				exportName := strings.TrimSuffix(resp, " (Enabled)")
				exportName = strings.TrimSuffix(exportName, " (Disabled)")
				for index, ec := range Configuration.ExportConfigurations {
					if ec.Name == exportName {
						Configuration.ExportConfigurations[index] = DefineExportConfiguration(ec)
						break
					}
				}
			} else {
				var config ExportConfiguration
				// Define new configuration
				Configuration.ExportConfigurations = append(Configuration.ExportConfigurations,
					DefineExportConfiguration(config))
			}
		}

		// Set up Severity Mappings
		resp, _ := PromptList(messages.SeverityConfig, []string{YES, NO})

		if resp == YES {
			for {
				var severityList []string
				for _, severity := range Configuration.SeverityMappings {
					severityList = append(severityList,
						fmt.Sprintf("%s : %s", severity.InsightAppSec, severity.Threadfix))
				}
				severityList = append(severityList, "Done")

				severity, _ := PromptList("Severity Mappings (InsightAppSec : Threadfix)", severityList)
				if severity == DONE {
					break
				}
				sev := strings.Split(severity, " : ")

				var currentSeverityNames []string
				for _, currentSeverity := range ThreadfixSeverities() {
					currentSeverityNames = append(currentSeverityNames, currentSeverity.Name)
				}
				threadfixSev, _ := PromptList(fmt.Sprintf("What Threadfix severity should be assigned to the [%s] "+
					"InsightAppSec severity?", sev[0]), currentSeverityNames)
				for index, s := range Configuration.SeverityMappings {
					if s.InsightAppSec == sev[0] {
						Configuration.SeverityMappings[index].Threadfix = threadfixSev
						log.Info(fmt.Sprintf("Assigning InsightAppSec severity [%s] to Threadfix severity [%s]",
							s.InsightAppSec, threadfixSev))
						break
					}
				}
			}
		}

		return true, Configuration
	} else {
		return false, Configuration
	}
}

func PromptList(label string, list []string) (string, error) {
	prompt := promptui.Select{
		Label: label,
		Items: list,
	}
	var result string
	var err error
	_, result, err = prompt.Run()
	if err != nil {
		return result, errors.New(fmt.Sprintf("Prompt failed %v\n", err))
	} else {
		return result, nil
	}
}

func PromptContinue() (string, error) {
	prompt := promptui.Select{
		Label:    "Continue?",
		Items: []string{YES, NO},
	}
	var result string
	var err error
	_, result, err = prompt.Run()
	if err != nil {
		return result, errors.New(fmt.Sprintf("Prompt failed %v\n", err))
	} else {
		return result, nil
	}
}

func StringPrompt(label string, sensitive bool, def string) (string, error) {
	validate := func(input string) error {
		return nil
	}

	prompt := promptui.Prompt{
		Label:    label,
		Validate: validate,
		Default:  def,
	}

	if sensitive {
		prompt.Mask = '*'

		string, err := prompt.Run()
		return shared.Encrypt(string), err
	}

	return prompt.Run()
}

func ConfirmSave(configuration *SettingsConf) bool {
	prompt := promptui.Select{
		Label:    "Save Configuration?",
		Items: []string{YES, NO},
	}
	var result string
	var err error
	_, result, err = prompt.Run()
	if err != nil {
		fmt.Println("Prompt failed %v\n", err)
		return false
	} else if result == NO {
		return false
	} else {
		requestByte, _ := json.Marshal(Configuration)
		requestReader := bytes.NewReader(requestByte)
		if err := viper.MergeConfig(requestReader); err != nil {
			log.Infof("Failed to update configuration: %s", err)
		} else {
			if err := viper.WriteConfig(); err != nil {
				panic(fmt.Sprintf("Failed to write configuration changes: %s", err))
			}
		}

		return true
	}
}

func DefineExportConfiguration(configuration ExportConfiguration) ExportConfiguration {
	configuration.ApplicationScope, _ = StringPrompt("What InsightAppSec Applications are within scope? You " +
		"may provide a regular expression to match Applications by name. This will determine which applications' " +
		"scans will be imported into Threadfix",
		false, configuration.ApplicationScope)
	configuration.ScanConfigFilter, _ = StringPrompt("Please define a Scan Config filter to limit the scans " +
		"within scope. You may provide a regular expression to match Scan Configs by name", false,
		configuration.ScanConfigFilter)
	resp, _ := PromptList("Only import the most recent InsightAppSec scan when run?", []string{YES, NO})
	if resp == YES {
		configuration.LastScanOnly = true
	} else {
		configuration.LastScanOnly = false

		// How many days back for initial scan
		resp, _ = StringPrompt("You have chosen to import historical scans as the integration is run. Past " +
			"scans will be imported from oldest to newest and provide the ability to import historical scan data. " +
			"How many days back from the initial import should be included?", false,
			strconv.Itoa(configuration.InitialImportMaxDays))
		configuration.InitialImportMaxDays, _ = strconv.Atoi(resp)
	}
	configuration.Name, _ = StringPrompt("Please provide a name for this configuration", false,
		configuration.Name)
	applicationMapping, _ := PromptList("Would you like to define a single Threadfix application where these " +
		"scans will be imported, or should scans be imported to a Threadfix application that is based on the " +
		"InsightAppSec application name?",
		[]string{"Define single Threadfix application name", "Based on InsightAppSec application name"})
	if applicationMapping == "Define single Threadfix application name" {
		configuration.MapApplicationByName = false

		// Ask for Threadfix Application Name
		configuration.ThreadfixApplicationName, _ = StringPrompt("Please provide the name of the Threadfix " +
			"application for the scans of this configuration", false, configuration.ThreadfixApplicationName)
	} else {
		configuration.MapApplicationByName = true
	}
	// Ask for Threadfix Team Name
	configuration.ThreadfixTeamName, _ = StringPrompt("Please provide the name of the Threadfix Team",
		false, configuration.ThreadfixTeamName)
	resp, _ = PromptList("Enable Configuration?", []string{YES, NO})
	if resp == YES {
		configuration.Enabled = true
	} else {
		configuration.Enabled = false
	}

	return configuration
}

func ThreadfixSeverities() []threadfix.VulnerabilitySeverity {
	var threadfixConfig = threadfix.ThreadfixConfiguration{
		APIKey:   shared.Decrypt(Configuration.Connections.Threadfix.Apikey),
		Host:     Configuration.Connections.Threadfix.Host,
		Port:     Configuration.Connections.Threadfix.Port,
	}

	var apiConfig = shared.APIConfiguration{Timeout: 30, RestyClient: resty.New()}
	var apiClient = shared.APIClient{Config: apiConfig}

	var threadfix = threadfix.API{Config: threadfixConfig, APIClient: apiClient}

	severities, _ := threadfix.ListSeverities()
	return severities.SeveritiesMetadata
}