package integration

type SettingsConf struct {
	Version              string                `yaml:"version"`
	Connections          ConnectionsConf       `yaml:"connections"`
	ExportConfigurations []ExportConfiguration `yaml:"exportConfigurations"`
	SeverityMappings     []SeverityMapping     `yaml:"severityMappings"`
	InternalScheduler    string                `yaml:"internalScheduler"`
	Logging              LoggingConf           `yaml:"logging"`
	Metrics              MetricsConf           `yaml:"metrics"`
}

type InsightAppSecConnection struct {
	Region string `yaml:"region"`
	Apikey string `yaml:"apikey"`
}

type ThreadfixConnection struct {
	Host   string `yaml:"host"`
	Port   string `yaml:"port"`
	Apikey string `yaml:"apikey"`
}

type ConnectionsConf struct {
	InsightAppSec InsightAppSecConnection `yaml:"insightappsec"`
	Threadfix     ThreadfixConnection     `yaml:"threadfix"`
}

type LoggingConf struct {
	Directory string `yaml:"directory"`
	Filename  string `yaml:"filename"`
	Level     string `yaml:"level"`
	Stdout    bool   `yaml:"stdout"`
}

type MetricsConf struct {
	Directory string `yaml:"directory"`
	Filename  string `yaml:"filename"`
	Pretty    bool   `yaml:"pretty"`
}

type SeverityMapping struct {
	Threadfix     string `yaml:"threadfix"`
	InsightAppSec string `yaml:"insightappsec"`
}

type ExportConfiguration struct {
	Name                     string `yaml:"name"`
	Enabled                  bool   `yaml:"enabled"`
	ApplicationScope         string `yaml:"application_scope"`
	ScanConfigFilter         string `yaml:"scan_config_filter"`
	LastScanOnly             bool   `yaml:"last_scan_only"`
	InitialImportMaxDays     int    `yaml:"initial_import_max_days"`
	MapApplicationByName     bool   `yaml:"map_application_by_name"`
	ThreadfixApplicationName string `yaml:"threadfix_application_name"`
	ThreadfixTeamName        string `yaml:"threadfix_team_name"`
}
