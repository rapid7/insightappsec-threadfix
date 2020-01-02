package cmd

import (
	"fmt"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/integration"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// configureCmd represents the configure command
var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure the Rapid7 InsightAppSec Threadfix integration",
	Long: `Used to initiate prompts for configuring the InsightAppSec Threadfix integration. If run for the first time,
the configuration prompts will take you through configuring connections to InsightAppSec and Threadfix followed by 
adding export configurations. If the configuration has already been configured, prompts will include past answers to
ease configuration.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Build configuration struct
		settings := &integration.SettingsConf{}
		err := viper.Unmarshal(settings)

		logging.Setup(
			settingsConf.Logging.Directory,
			settingsConf.Logging.Filename,
			settingsConf.Logging.Level,
			settingsConf.Logging.Stdout,)

		if err != nil {
			logging.Logger.Fatalf("Unable to parse configuration file, %v", err)
		}
		integration.Configuration = settings
		shared.ConfigFile = viper.ConfigFileUsed()

		var modified bool
		// Check if configuration previously defined
		_, message := integration.ConfigComplete()
		modified, configuration := integration.Configure(message)

		if modified {
			confirm := integration.ConfirmSave(configuration)
			if confirm {
				fmt.Println(fmt.Sprintf("Configuration has been saved to %s", viper.ConfigFileUsed()))
			} else {
				fmt.Println("Discarding configuration changes")
			}
		}
	},
}

var printConfigureTimes = &cobra.Command{
	Use:   "print",
	Short: "Print the current configuration",
	Long: "Print the current configuration file with defined settings to standard out.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Current configuration file contents:")
		settings := &integration.SettingsConf{}
		err := viper.Unmarshal(settings)
		if err != nil {
			logging.Logger.Fatalf("Unable to parse configuration file, %v", err)
		} else {
			d, err := yaml.Marshal(&settings)
			if err != nil {
				logging.Logger.Fatalf("error: %v", err)
			}
			fmt.Printf("---\n%s", string(d))
		}
	},
}

func init() {
	rootCmd.AddCommand(configureCmd)
	configureCmd.AddCommand(printConfigureTimes)
}
