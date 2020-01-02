package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/components/insightappsec"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/components/threadfix"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared/logging"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared/metrics"
	"io/ioutil"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
)

var SeverityMappings []SeverityMapping
var IasClient insightappsec.API
var ThreadfixClient threadfix.API
var PersistScanFiles bool

func ProcessApp(threadfixApp threadfix.Application, exportConfiguration ExportConfiguration, initialImport bool) (bool, int) {
	var numScansImported int
	var err error
	if initialImport {
		logging.Logger.Infof("Performing initial import of scans for Threadfix App: %s; Last Scan Only: %t, " +
			"Application Scope: %s",
			threadfixApp.AppData.Name,
			exportConfiguration.LastScanOnly,
			exportConfiguration.ApplicationScope)
		// Initial import
		numScansImported, err = ImportInitialScans(threadfixApp,
			exportConfiguration.LastScanOnly,
			exportConfiguration.InitialImportMaxDays,
			exportConfiguration.ApplicationScope,
			exportConfiguration.ScanConfigFilter)

		if err != nil {
			logging.Logger.Errorf("Failed during initial import of scans to %s Threadfix Application",
				threadfixApp.AppData.Name)
			return false, 0
		}

		logging.Logger.Infof("%d scan(s) queued during initial import to %s Threadfix Application",
			numScansImported,
			threadfixApp.AppData.Name)
	} else {
		logging.Logger.Infof("Performing import of scans for Threadfix App: %s; Last Scan Only: %t, Application Scope: %s",
			threadfixApp.AppData.Name,
			exportConfiguration.LastScanOnly,
			exportConfiguration.ApplicationScope)
		// All other imports
		numScansImported, err = ImportScans(threadfixApp,
			exportConfiguration.LastScanOnly,
			exportConfiguration.ApplicationScope,
			exportConfiguration.ScanConfigFilter)

		if err != nil {
			logging.Logger.Errorf("Failed to import scans to %s Threadfix Application", threadfixApp.AppData.Name)
			return false, 0
		}

		logging.Logger.Infof("%d scan(s) queued to be imported to %s Threadfix Application",
			numScansImported,
			threadfixApp.AppData.Name)
	}

	return true, numScansImported
}

func ProcessConfiguration(exportConfiguration ExportConfiguration) bool {
	// Get InsightAppSec Apps by Name
	var insightappsecApps = IasClient.GetAppsByName(exportConfiguration.ApplicationScope)
	logging.Logger.Debugf("Number of apps returned for search: %v\n", len(insightappsecApps))

	if exportConfiguration.MapApplicationByName {
		logging.Logger.Infof("Mapping Threadfix and InsightAppSec applications by name for export configuration %s",
			exportConfiguration.Name)

		// Process app name == app name
		for _, insightappsecApp := range insightappsecApps {
			processStart := time.Now()
			// Get App of Threadfix Application Name
			threadfixApp, err := ThreadfixClient.GetAppByName(exportConfiguration.ThreadfixTeamName,
				insightappsecApp.Name)
			if err != nil {
				logging.Logger.Errorf("Failed to return Threadfix Application with name %s: %s", insightappsecApp.Name, err)
				return false
			}

			// Set Application Scope name to specific Insightappsec app name
			exportConfiguration.ApplicationScope = insightappsecApp.Name

			// Get Scans for Threadfix App
			threadfixAppScans, _ := ThreadfixClient.ListScans(threadfixApp.AppData.ID)

			_, numScans := ProcessApp(threadfixApp, exportConfiguration, len(threadfixAppScans) == 0)

			metrics.Metrics.
				WithField("start_time", processStart).
				WithField("end_time", time.Now()).
				WithField("export_configuration", exportConfiguration.Name).
				WithField("application_name", insightappsecApp.Name).
				WithField("duration", time.Since(processStart).Seconds()).
				WithField("number_of_apps", len(insightappsecApps)).
				WithField("number_of_scans", numScans).
				Infof("MapApplicationByName Ingestion")
		}
	} else {
		// Process all apps/scans in scope to single threadfix app
		// Get App of Threadfix Application Name
		threadfixApp, err := ThreadfixClient.GetAppByName(exportConfiguration.ThreadfixTeamName,
			exportConfiguration.ThreadfixApplicationName)
		logging.Logger.Infof("Mapping InsightAppSec applications to %s Threadfix application (ID: %d) ",
			exportConfiguration.ThreadfixApplicationName, threadfixApp.AppData.ID)

		if err != nil {
			logging.Logger.Errorf("Failed to return Threadfix Application with name %s: %s",
				exportConfiguration.ThreadfixApplicationName, err)
			return false
		}

		// Get Scans for Threadfix App
		threadfixAppScans, _ := ThreadfixClient.ListScans(threadfixApp.AppData.ID)

		processStart := time.Now()
		_, numScans := ProcessApp(threadfixApp, exportConfiguration, len(threadfixAppScans) == 0)

		metrics.Metrics.
			WithField("start_time", processStart).
			WithField("end_time", time.Now()).
			WithField("export_configuration", exportConfiguration.Name).
			WithField("application_name", exportConfiguration.ThreadfixApplicationName).
			WithField("duration", time.Since(processStart).Seconds()).
			WithField("number_of_apps", len(insightappsecApps)).
			WithField("number_of_scans", numScans).
			Infof("BulkApplication Ingestion")
	}

	return true
}

func ProcessConfigurations(exportConfigurations []ExportConfiguration) {
	for _, exportConfiguration := range exportConfigurations {
		if exportConfiguration.Enabled {
			logging.Logger.Info(fmt.Sprintf("Begin processing [%s] export configuration", exportConfiguration.Name))
			ProcessConfiguration(exportConfiguration)
			logging.Logger.Info(fmt.Sprintf("End processing [%s] export configuration", exportConfiguration.Name))
		}
	}
}

func ImportScan(scanId string, appName string, teamName string) (int, error) {
	var numSubmittedScans = 0

	threadfixApp, err := ThreadfixClient.GetAppByName(teamName, appName)
	if threadfixApp.AppData.Name == "" || err != nil {
		fmt.Println(fmt.Sprintf("Failed to retrieve Threadfix application for App Name: %s, Team Name: %s",
			appName, teamName))
		os.Exit(1)
	}

	scan, err := IasClient.GetScanById(scanId)
	if scan.ID == "" || err != nil {
		fmt.Println(fmt.Sprintf("Unable to retrieve scan by scan ID %s; verify scan ID and try again", scanId))
		os.Exit(1)
	}

	var vulns = IasClient.GetVulnsByScanId(scanId)
	threadfixScan := ConvertScan(scan, vulns)

	// Write to filesystem for persisting scan file
	if PersistScanFiles {
		PersistScan(scan, threadfixScan)
	}

	logging.Logger.Infof("Beginning Threadfix scan upload. %s", threadfixScan.ExecutiveSummary)
	uploadStart := time.Now()
	response, err := ThreadfixClient.UploadScan(threadfixApp.AppData.ID, threadfixScan)

	if err != nil {
		logging.Logger.Error("Error uploading scan to Threadfix in insightappsec_threadfix/ImportInitialScans", err)
	} else {
		if response.Success == true {
			logging.Logger.Infof("Threadfix scan successfully submitted for upload. %s", threadfixScan.ExecutiveSummary)
			numSubmittedScans++
		}
	}
	metrics.Metrics.
		WithField("start_time", uploadStart).
		WithField("end_time", time.Now()).
		WithField("executive_summary", threadfixScan.ExecutiveSummary).
		WithField("duration", time.Since(uploadStart).Seconds()).
		WithField("number_of_findings", len(threadfixScan.Findings)).
		Infof("Scan Upload")

	logging.Logger.Infof("%d scans submitted for upload to Threadfix", numSubmittedScans)
	return numSubmittedScans, nil
}

func ImportInitialScans(threadfixApp threadfix.Application, importLastScanOnly bool, importMaxDays int, appFilter string, scanConfigFilter string) (int, error) {
	var applications = IasClient.GetAppsByName(appFilter)
	var scans []insightappsec.Scan
	var filteredScans []insightappsec.Scan
	var numSubmittedScans = 0

	// Filter by application
	for _, app := range applications {
		var appFilteredScans = IasClient.GetScansByAppId(app.ID)
		scans = append(scans, appFilteredScans...)
	}

	// Filter by scan config
	scans, err := FilterByScanConfig(scans, scanConfigFilter)

	if err != nil {
		logging.Logger.Error("Error filtering by scan config in insightappsec_threadfix/ImportInitialScans", err)
		return -1, errors.New(err.Error())
	}

	// Filter by date
	if importLastScanOnly {
		filteredScans = append(filteredScans, scans[0]) // First scan = most recent
	} else {
		var today = time.Now().UTC()
		var subtractedDate = today.AddDate(0, 0, -importMaxDays)
		var truncatedDate = subtractedDate.Truncate(24 * time.Hour)
		filteredScans = FilterByDate(scans, truncatedDate)
	}

	// Convert IAS scans to Threadfix scans; process oldest to newest
	for _, scan := range reverse(filteredScans) {
		var vulns = IasClient.GetVulnsByScanId(scan.ID)
		threadfixScan := ConvertScan(scan, vulns)

		// Write to filesystem for persisting scan file
		if PersistScanFiles {
			PersistScan(scan, threadfixScan)
		}

		logging.Logger.Infof("Beginning Threadfix scan upload. %s", threadfixScan.ExecutiveSummary)
		uploadStart := time.Now()
		response, err := ThreadfixClient.UploadScan(threadfixApp.AppData.ID, threadfixScan)

		if err != nil {
			logging.Logger.Error("Error uploading scan to Threadfix in insightappsec_threadfix/ImportInitialScans", err)
		} else {
			if response.Success == true {
				logging.Logger.Infof("Threadfix scan successfully submitted for upload. %s", threadfixScan.ExecutiveSummary)
				numSubmittedScans++
			} else {
				logging.Logger.Errorf("Unsuccessful scan upload: %s", response.Message)
			}
		}
		metrics.Metrics.
			WithField("start_time", uploadStart).
			WithField("end_time", time.Now()).
			WithField("executive_summary", threadfixScan.ExecutiveSummary).
			WithField("duration", time.Since(uploadStart).Seconds()).
			WithField("number_of_findings", len(threadfixScan.Findings)).
			Infof("Scan Upload")
	}

	logging.Logger.Infof("%d scans submitted for upload to Threadfix", numSubmittedScans)
	return numSubmittedScans, nil
}

func ImportScans(threadfixApp threadfix.Application, importLastScanOnly bool, appFilter string, scanConfigFilter string) (int, error) {
	var applications = IasClient.GetAppsByName(appFilter)
	var scans []insightappsec.Scan
	var filteredScans []insightappsec.Scan
	var numSubmittedScans = 0

	// Filter by application
	for _, app := range applications {
		var appFilteredScans = IasClient.GetScansByAppId(app.ID)
		scans = append(scans, appFilteredScans...)
	}

	// Filter by scan config
	scans, scanConfigError := FilterByScanConfig(scans, scanConfigFilter)

	if scanConfigError != nil {
		logging.Logger.Error("Error filtering by scan config in insightappsec_threadfix/ImportScans", scanConfigError)
		return -1, errors.New(scanConfigError.Error())
	}

	// Get Threadfix scans to check latest date/time
	existingScans, threadfixError := ThreadfixClient.ListScans(threadfixApp.AppData.ID)

	if threadfixError != nil {
		logging.Logger.Error("Error retrieving Threadfix scans in insightappsec_threadfix/ImportScans", threadfixError)
		return -1, errors.New(threadfixError.Error())
	}

	if len(existingScans) > 0 {
		var latestThreadfixScanDate = existingScans[0].UpdatedDate
		var formattedDate = time.Unix(int64(latestThreadfixScanDate/1000), 0) // Convert from ms to sec
		scans = FilterByDate(scans, formattedDate)
	}

	if importLastScanOnly {
		if len(scans) > 0 {
			filteredScans = append(filteredScans, scans[0]) // First scan = most recent
		}
	} else {
		filteredScans = scans
	}

	// Convert InsightAppSec scans to Threadfix scans and Import
	for _, scan := range filteredScans {
		var vulns = IasClient.GetVulnsByScanId(scan.ID)

		threadfixScan := ConvertScan(scan, vulns)

		// Write to filesystem for persisting scan file
		if PersistScanFiles {
			PersistScan(scan, threadfixScan)
		}

		logging.Logger.Infof("Beginning Threadfix scan upload. %s", threadfixScan.ExecutiveSummary)
		uploadStart := time.Now()
		response, err := ThreadfixClient.UploadScan(threadfixApp.AppData.ID, threadfixScan)

		if err != nil {
			logging.Logger.Error("Error uploading scan to Threadfix in insightappsec_threadfix/ImportScans", err)
		} else {
			if response.Success == true {
				logging.Logger.Infof("Threadfix scan successfully submitted for upload. %s", threadfixScan.ExecutiveSummary)
				numSubmittedScans++
			}
		}
		metrics.Metrics.
			WithField("start_time", uploadStart).
			WithField("end_time", time.Now()).
			WithField("executive_summary", threadfixScan.ExecutiveSummary).
			WithField("duration", time.Since(uploadStart).Seconds()).
			WithField("number_of_findings", len(threadfixScan.Findings)).
			Infof("Scan Upload")
	}

	logging.Logger.Infof("%d scans submitted for upload to Threadfix", numSubmittedScans)
	return numSubmittedScans, nil
}

// Convert InsightAppSec scan to Threadfix scan for importing
func ConvertScan(scan insightappsec.Scan, vulnerabilities []insightappsec.Vulnerability) threadfix.ThreadfixScan {
	convertStart := time.Now()
	// Convert InsightAppSec Vulnerabilities to Findings
	var findings = ConvertVulnerabilities(vulnerabilities)

	var created = FormatDate(scan.SubmitTime)
	var updated = FormatDate(scan.CompletionTime)
	var exported = FormatDate(time.Now().UTC().String())

	var threadfixScan = threadfix.ThreadfixScan{
		Created:          created,
		Updated:          updated,
		Exported:         exported,
		CollectionType:   "DAST",
		Source:           threadfix.ScannerSource,
		ExecutiveSummary: fmt.Sprintf("Application ID: %s, Scan ID: %s", scan.App.ID, scan.ID),
		Findings: findings,
	}

	logging.Logger.Infof("Scan conversion for scan ID %s completed; ready for upload to Threadfix", scan.ID)
	metrics.Metrics.
		WithField("start_time", convertStart).
		WithField("end_time", time.Now()).
		WithField("duration", time.Since(convertStart).Seconds()).
		WithField("scan_id", scan.ID).
		WithField("number_of_findings", len(findings)).
		Infof("Convert Scan")

	return threadfixScan
}

// Convert InsightAppSec vulnerability to a Threadfix finding while fetching attack documentation and module details
func ConvertVulnerabilities(vulnerabilities []insightappsec.Vulnerability) []threadfix.Finding {
	var findings []threadfix.Finding
	modulesCache := make(map[string]insightappsec.Module)             // Used for caching
	attackCache := make(map[string]insightappsec.AttackDocumentation) // Used for caching
	modulesApiRequests := 0
	modulesCacheRequests := 0
	attackApiRequests := 0
	attackCacheRequests := 0

	if len(vulnerabilities) == 0 {
		logging.Logger.Info("No vulnerabilities for scan")
		return findings
	}

	for _, vulnerability := range vulnerabilities {
		preferredVariance := PreferredVariance(vulnerability.Variances)
		// Fetch Module details from cache or via API
		var module insightappsec.Module
		if val, ok := modulesCache[preferredVariance.Module.ID]; ok {
			module = val
			modulesCacheRequests = modulesCacheRequests + 1
		} else {
			module, _ = IasClient.GetModule(preferredVariance.Module.ID)
			modulesCache[preferredVariance.Module.ID] = module
			modulesApiRequests = modulesApiRequests + 1
		}
		// Fetch Attack Documentation from cache or via API
		var attackDocumentation insightappsec.AttackDocumentation
		key := fmt.Sprintf("%s-%s", preferredVariance.Module.ID, preferredVariance.Attack.ID)
		if val, ok := attackCache[key]; ok {
			attackDocumentation = val
			attackCacheRequests = attackCacheRequests + 1
		} else {
			attackDocumentation, _ = IasClient.GetAttackDocumentation(preferredVariance.Module.ID, preferredVariance.Attack.ID)
			attackCache[key] = attackDocumentation
			attackApiRequests = attackApiRequests + 1
		}

		var attackRequest string
		var attackResponse string
		if len(preferredVariance.AttackExchanges) > 0 {
			attackRequest = preferredVariance.AttackExchanges[0].Request
			attackResponse = preferredVariance.AttackExchanges[0].Response
		}

		threadfixSeverity, err := MapSeverity(vulnerability.Severity)
		var mappings = MapAttackDocumentation(attackDocumentation)

		if err != nil {
			logging.Logger.Errorf("Failed to map status: %s", err) // TODO: Validate what occurs when uploading scan with "Unknown" Severity
			threadfixSeverity = "Unknown"
		}

		findings = append(findings, threadfix.Finding{
			NativeID:              vulnerability.ID,
			Severity:              threadfixSeverity,
			NativeSeverity:        vulnerability.Severity,
			Summary:               module.Name,
			Description:           module.Description,
			ScannerDetail:         attackDocumentation.Description,
			ScannerRecommendation: attackDocumentation.Recommendation,
			DynamicDetails: threadfix.DynamicDetails{
				SurfaceLocation: threadfix.SurfaceLocation{
					URL:            vulnerability.RootCause.URL,
					Parameter:      vulnerability.RootCause.Parameter,
					AttackString:   preferredVariance.AttackValue,
					AttackRequest:  attackRequest,
					AttackResponse: attackResponse,
				},
			},
			Mappings: mappings,
			Comments: IasClient.GetVulnComments(),
		})
	}

	logging.Logger.Infof("%d InsightAppSec Vulnerabilities converted to Threadfix Findings for scan",
		len(vulnerabilities))
	metrics.Metrics.
		WithField("module_cache", modulesCacheRequests).
		WithField("module_api", modulesApiRequests).
		WithField("attack_documentation_cache", attackCacheRequests).
		WithField("attack_documentation_api", attackApiRequests).
		Infof("ScanDetailsMetrics Ingestion")

	return findings
}

func PreferredVariance(variances []insightappsec.Variance) insightappsec.Variance {
	var preferredVariance insightappsec.Variance
	prevCount := -1

	// Return variance with most non-nil fields; useful in identifying variance with most information to process
	for _, variance := range variances {
		v := reflect.ValueOf(variance)

		count := 0
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).Interface() != "" && v.Field(i).Interface() != nil {
				count = count + 1
			}
		}

		if count > prevCount {
			preferredVariance = variance
			prevCount = count
		}
	}
	return preferredVariance
}

// Map InsightAppSec Severity to Threadfix Severity based on configuration file
func MapSeverity(insightappsecSeverity string) (string, error) {
	var threadfixSeverity string

	for _, severityMapping := range SeverityMappings {
		if strings.EqualFold(severityMapping.InsightAppSec, insightappsecSeverity) {
			threadfixSeverity = severityMapping.Threadfix
			break
		}
	}

	if threadfixSeverity == "" {
		return threadfixSeverity, errors.New(fmt.Sprintf("threadfix severity mapping does not exist for "+
			"InsightAppSec severity: %s", insightappsecSeverity))
	}

	return threadfixSeverity, nil
}

func FilterByScanConfig(scans []insightappsec.Scan, regex string) ([]insightappsec.Scan, error) {
	var filteredScans []insightappsec.Scan

	for _, scan := range scans {
		var scanConfig, err = IasClient.GetScanConfigByID(scan.ScanConfig.ID)
		if err != nil {
			logging.Logger.Error("Error in insightappsec_threadfix/FilterByScanConfig", err)
			continue
		}

		match, _ := regexp.MatchString(regex, scanConfig.Name)
		if match {
			filteredScans = append(filteredScans, scan)
		}
	}
	logging.Logger.Debugf("Scan configuration filtering: %d scans filtered out of %d original scans with regex: %s",
		len(filteredScans), len(scans), regex)
	return filteredScans, nil
}

func FilterByDate(scans []insightappsec.Scan, date time.Time) []insightappsec.Scan {
	var filteredScans []insightappsec.Scan

	for _, scan := range scans {
		trimTime := strings.Split(scan.CompletionTime, ".") // Trim millisecond from time to normalize between products
		scanCompleted, _ := time.Parse(time.RFC3339, trimTime[0]+"Z")

		if scanCompleted.After(date) {
			filteredScans = append(filteredScans, scan)
		}
	}
	logging.Logger.Debugf("Date filtering: %d scans filtered out of %d original scans with the date %s",
		len(filteredScans), len(scans), date.String())
	return filteredScans
}

func MapAttackDocumentation(attackDoc insightappsec.AttackDocumentation) []threadfix.Mapping {
	mappings := []threadfix.Mapping{}
	var cweMatch = false

	for key, _ := range attackDoc.References {
		var mapping threadfix.Mapping
		var mappingType = strings.Split(key, "-")

		if mappingType[0] == shared.CWE {
			mapping.MappingType = mappingType[0]
			mapping.Value = mappingType[1]
			// Only label a single CWE instance as primary
			if cweMatch == false {
				mapping.Primary = true
				cweMatch = true
			}
		} else {
			mapping.MappingType = threadfix.ToolVendor
			mapping.Value = key
			mapping.Primary = false
			mapping.VendorOtherType = mappingType[0]
		}

		mappings = append(mappings, mapping)
	}
	return mappings
}

func FormatDate(dateTime string) string {
	var splitString = strings.Split(dateTime, ".")
	var stringDate = splitString[0] + "Z"
	var formattedDate = strings.Replace(stringDate, " ", "T", -1)

	return formattedDate
}

func PersistScan(scan insightappsec.Scan, threadfixScan threadfix.ThreadfixScan) {
	if scanJson, err := json.Marshal(threadfixScan); err != nil {
		logging.Logger.Errorf("Error marshaling JSON for scan to persist to filesystem. Scan ID %s", scan.ID)
	} else {
		filename := fmt.Sprintf("InsightAppSec-ScanID-%s.json", scan.ID)
		_ = ioutil.WriteFile(filename, scanJson, 0600)
		logging.Logger.Infof("Persisted scan ID %s to filesystem: %s", scan.ID, filename)
	}
}

// Reverse order of scans to older to newest to ensure they are processed in the proper order
func reverse(scans []insightappsec.Scan) []insightappsec.Scan {
	for i := 0; i < len(scans)/2; i++ {
		j := len(scans) - i - 1
		scans[i], scans[j] = scans[j], scans[i]
	}
	return scans
}
