package cmd

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/components/insightappsec"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/components/threadfix"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/integration"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared/logging"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared/metrics"
	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"os/signal"
)

var cfgFile string
var settingsConf integration.SettingsConf

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "rapid7-insightappsec-threadfix",
	Short: "Integration between Rapid7 InsightAppSec and Threadfix",
	Long: `This application is an integration between Rapid7 InsightAppSec and Threadfix. It automates the generation 
and formatting of findings from InsightAppSec scans and then imports them into Threadfix. Once imported, scans and
findings can be correlated with other application security feeds and searched within the Threadfix management 
platform`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		// Setup logging
		logging.Setup(
			settingsConf.Logging.Directory,
			settingsConf.Logging.Filename,
			settingsConf.Logging.Level,
			settingsConf.Logging.Stdout,)
		// Setup metrics tracking
		metrics.Setup(
			settingsConf.Metrics.Directory,
			settingsConf.Metrics.Filename,
			settingsConf.Metrics.Pretty)

		var iasConfig = insightappsec.InsightAppSecConfiguration{
			Region:   settingsConf.Connections.InsightAppSec.Region,
			APIKey:   shared.Decrypt(settingsConf.Connections.InsightAppSec.Apikey),
			BasePath: "https://%s.api.insight.rapid7.com/ias/v1/"}

		var threadfixConfig = threadfix.ThreadfixConfiguration{
			APIKey:   shared.Decrypt(settingsConf.Connections.Threadfix.Apikey),
			Host:     settingsConf.Connections.Threadfix.Host,
			Port:     settingsConf.Connections.Threadfix.Port,
		}

		var apiConfig = shared.APIConfiguration{Timeout: 180, RestyClient: resty.New()}
		var apiClient = shared.APIClient{Config: apiConfig}

		var ias = insightappsec.API{Config: iasConfig, APIClient: apiClient}
		var threadfix = threadfix.API{Config: threadfixConfig, APIClient: apiClient}

		// Inject InsightAppSec and Threadfix Clients
		integration.IasClient = ias
		integration.ThreadfixClient = threadfix
		integration.SeverityMappings = settingsConf.SeverityMappings

		if persist, _ := cmd.Flags().GetBool("persist"); persist {
			integration.PersistScanFiles = true
		} else {
			integration.PersistScanFiles = false
		}

		scanId, _ := cmd.Flags().GetString("scan")
		adhoc, _ := cmd.Flags().GetBool("adhoc")
		if scanId != "" {
			app, _ := cmd.Flags().GetString("scan_app")
			if app == "" {
				fmt.Println("ERROR: Must define --scan_app flag when initiating with the --scan flag")
				os.Exit(1)
			}
			team, _ := cmd.Flags().GetString("scan_team")
			if team == "" {
				fmt.Println("ERROR: Must define --scan_team flag when initiating with the --scan flag")
				os.Exit(1)
			}
			integration.ImportScan(scanId, app, team)
		} else if adhoc {
			message := "Adhoc processing started"
			fmt.Println(message)
			logging.Logger.Info(message)
			integration.ProcessConfigurations(settingsConf.ExportConfigurations)
		} else {
			message := fmt.Sprintf("Intializing scheduler with cron: %s", settingsConf.InternalScheduler)
			logging.Logger.Info(message)
			// Set up scheduler
			c := cron.New(
				cron.WithLogger(cron.DefaultLogger))
			c.AddFunc(settingsConf.InternalScheduler, func() {integration.ProcessConfigurations(settingsConf.ExportConfigurations)})

			// Run forever more until termination
			go c.Start()
			sig := make(chan os.Signal)
			signal.Notify(sig, os.Interrupt, os.Kill)
			<-sig
			c.Stop()
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./config/settings.yaml)")

	// Only run once, no scheduling used
	rootCmd.Flags().BoolP("adhoc", "a", false, "Adhoc run of integration without the use of scheduling")

	// Save created scan files to filesystem
	rootCmd.Flags().BoolP("persist", "p", false, "Create and save generated scan files to filesystem; NOTE: this is for debugging purposes")

	// Upload specific scan by ID
	rootCmd.Flags().String("scan", "", "Provide an InsightAppSec scan ID to import an individual scan to Threadfix")
	rootCmd.Flags().String("scan_app", "", "Threadfix application for scan import; NOTE: required and only encorced when used with --scan flag")
	rootCmd.Flags().String("scan_team", "", "Threadfix team for scan import; NOTE: required and only enforced when used with --scan flag")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("./configs/")
		viper.SetConfigName("settings")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
		shared.ConfigFile = viper.ConfigFileUsed()
	} else {
		panic(fmt.Sprintf("Failed to read configuration file %s: %s", viper.ConfigFileUsed(), err))
	}

	// Unmarshal to struct
	err := viper.Unmarshal(&settingsConf)
	if err != nil {
		panic("Unable to unmarshal config")
	}
}