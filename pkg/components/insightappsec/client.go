package insightappsec

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared"
	log "github.com/sirupsen/logrus"
)

type API struct {
	Config    InsightAppSecConfiguration
	APIClient shared.APIClient
}

const UserAgent = "r7:insightappsec-threadfix-extension-1.0.1"

func (ias *API) DoSearch(searchType string, query string, index int, size int, sort string) []byte {
	var search = SearchParameters{Type: searchType, Query: query}
	var header = ias.FormatHeader()
	var endpoint = "search"
	var url = ias.FormatUrl(Url{Endpoint: endpoint, Index: index, Size: size, Sort: sort})
	var method = shared.ApiMethodPost

	var response, err = ias.APIClient.CallAPI(url, method, search, header)

	if err != nil {
		log.Error("Error in insightappsec/DoSearch", err)
		return nil
	}
	return response.Body()
}

func (ias *API) GetAppsByName(name string) []Application {
	var searchType = AppSearchType
	var query = fmt.Sprintf("app.name LIKE '%s'", name)
	var index = PageIndex
	var apps []Application
	var cont = true

	for cont {
		var searchData AppSearchResponse
		var response = ias.DoSearch(searchType, query, index, PageSize, "")
		json.Unmarshal(response, &searchData)
		apps = append(apps, searchData.Data...)

		if searchData.Metadata.TotalData <= len(apps) {
			cont = false
		} else {
			index = index + 1
		}
	}
	return apps
}

func (ias *API) GetScansByAppId(appId string) []Scan {
	var searchType = ScanSearchType
	var query = fmt.Sprintf("scan.app.id='%s'", appId)
	var index = PageIndex
	var scans []Scan
	var cont = true

	for cont {
		var searchData ScanSearchResponse
		var response = ias.DoSearch(searchType, query, index, PageSize, ScanDateSortDesc)
		json.Unmarshal(response, &searchData)
		scans = append(scans, searchData.Data...)

		if searchData.Metadata.TotalData <= len(scans) {
			cont = false
		} else {
			index = index + 1
		}
	}
	return scans
}

func (ias *API) GetScanById(scanId string) (Scan, error) {
	var header = ias.FormatHeader()
	var endpoint = "scans/" + scanId
	var url = ias.FormatUrl(Url{Endpoint: endpoint})
	var method = shared.ApiMethodGet
	var scan Scan

	var response, err = ias.APIClient.CallAPI(url, method, nil, header)

	if err != nil {
		log.Error("Error in insightappsec/GetScan", err)
		return scan, errors.New("error in insightappsec/GetScan")
	}
	json.Unmarshal(response.Body(), &scan)
	return scan, nil
}

func (ias *API) GetVulnsByScanId(scanId string) []Vulnerability {
	var searchType = VulnSearchType
	var query = fmt.Sprintf("vulnerability.scans.id='%s'", scanId)
	var vulns []Vulnerability
	var index = PageIndex
	var cont = true

	for cont {
		var searchData VulnerabilitySearchResponse
		var response = ias.DoSearch(searchType, query, index, PageSize, "")
		json.Unmarshal(response, &searchData)
		vulns = append(vulns, searchData.Data...)

		if searchData.Metadata.TotalData <= len(vulns) {
			cont = false
		} else {
			index = index + 1
		}
	}
	return vulns
}

func (ias *API) GetModule(moduleId string) (Module, error) {
	var header = ias.FormatHeader()
	var endpoint = "modules/" + moduleId
	var url = ias.FormatUrl(Url{Endpoint: endpoint})
	var method = shared.ApiMethodGet
	var module Module

	var response, err = ias.APIClient.CallAPI(url, method, nil, header)

	if err != nil {
		log.Error("Error in insightappsec/GetModule", err)
		return module, errors.New("error in insightappsec/GetModule")
	}
	json.Unmarshal(response.Body(), &module)
	return module, nil
}

func (ias *API) GetAttackDocumentation(moduleId string, attackId string) (AttackDocumentation, error) {
	var header = ias.FormatHeader()
	var endpoint = fmt.Sprintf("modules/%s/attacks/%s/documentation", moduleId, attackId)
	var url = ias.FormatUrl(Url{Endpoint: endpoint})
	var method = shared.ApiMethodGet
	var attackDoc AttackDocumentation

	var response, err = ias.APIClient.CallAPI(url, method, nil, header)

	if err != nil {
		log.Error("Error in insightappsec/GetAttackDocumentation", err)
		return attackDoc, errors.New("error in insightappsec/GetAttackDocumentation")
	}
	json.Unmarshal(response.Body(), &attackDoc)
	return attackDoc, nil
}

func (ias *API) GetScanConfigs() ([]ScanConfig, error) {
	var header = ias.FormatHeader()
	var endpoint = "scan-configs"
	var index = PageIndex
	var method = shared.ApiMethodGet
	var scanConfigs []ScanConfig
	var cont = true

	for cont {
		var scanConfigData ScanConfigResponse
		var url = ias.FormatUrl(Url{Endpoint: endpoint, Index: index, Size: PageSize})
		var response, err = ias.APIClient.CallAPI(url, method, nil, header)

		if err != nil {
			log.Error("Error in insightappsec/GetScanConfigs", err)
			return scanConfigs, errors.New(err.Error())
		}

		json.Unmarshal(response.Body(), &scanConfigData)
		scanConfigs = append(scanConfigs, scanConfigData.Data...)

		if scanConfigData.Metadata.TotalData <= len(scanConfigs) {
			cont = false
		} else {
			index = index + 1
		}
	}
	return scanConfigs, nil
}

func (ias *API) GetScanConfigByID(id string) (ScanConfig, error) {
	var scanConfig ScanConfig
	var scanConfigs, err = ias.GetScanConfigs()

	if err != nil {
		log.Error("Error in insightappsec/GetScanConfigByID", err)
		return scanConfig, errors.New("error in insightappsec/GetScanConfigByID")
	}

	for _, config := range scanConfigs {
		if config.ID == id {
			scanConfig = config
			break
		}
	}
	return scanConfig, nil
}

// TODO Retrieve vuln comments via API when it can be done in a non-intensive way; Currently would be a request per vulnerability
func (ias *API) GetVulnComments() []string {
	comments := []string{}
	return comments
}

func (ias *API) FormatUrl(url Url) string {
	var fullUrl = fmt.Sprintf(ias.Config.BasePath, ias.Config.Region)
	fullUrl = fullUrl + url.Endpoint

	var index int
	var size int
	if url.Index == index && url.Size == size {
		return fullUrl
	}
	var queryString = fmt.Sprintf("?size=%d&index=%d", url.Size, url.Index)
	fullUrl = fullUrl + queryString + url.Sort

	return fullUrl
}

func (ias *API) FormatHeader() map[string]string {
	var header = make(map[string]string)
	header["x-api-key"] = ias.Config.APIKey
	header["User-Agent"] = UserAgent

	return header
}
