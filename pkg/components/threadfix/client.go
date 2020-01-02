package threadfix

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared/logging"
	log "github.com/sirupsen/logrus"
)

type API struct {
	Config    ThreadfixConfiguration
	APIClient shared.APIClient
}

func (tf *API) UploadScan(appId int, scan ThreadfixScan) (UploadScanResponse, error) {
	var endpoint = fmt.Sprintf("rest/v2.5/applications/%d/upload", appId)
	var header = tf.FormatHeader()
	var url = tf.FormatUrl(endpoint)
	var uploadResponse UploadScanResponse
	var scanJson, marshalError = json.Marshal(scan)

	if marshalError != nil {
		log.Error("Error marshaling JSON in threadfix/UploadScan", marshalError)
		return uploadResponse, errors.New(marshalError.Error())
	}

	var response, apiError = tf.APIClient.Config.RestyClient.R().
		SetFileReader("file", scan.ExecutiveSummary+".threadfix", bytes.NewReader(scanJson)).
		SetContentLength(true).
		SetHeaders(header).
		Post(url)

	if apiError != nil {
		log.Error("Error in threadfix/UploadScan", apiError)
		return uploadResponse, errors.New(apiError.Error())
	}
	json.Unmarshal(response.Body(), &uploadResponse)
	return uploadResponse, nil
}

func (tf *API) ListScans(appId int) ([]ScanMetadata, error) {
	var endpoint = fmt.Sprintf("rest/applications/%d/scans", appId)
	var header = tf.FormatHeader()
	var url = tf.FormatUrl(endpoint)
	var scansResponse ListScansResponse
	var rapid7Scans []ScanMetadata
	var method = shared.ApiMethodGet

	var response, err = tf.APIClient.CallAPI(url, method, nil, header)

	if err != nil {
		log.Error("Error in threadfix/ListScans", err)
		return rapid7Scans, errors.New("error in threadfix/ListScans")
	}
	json.Unmarshal(response.Body(), &scansResponse)

	for _, scan := range scansResponse.ScanMetadata {
		if scan.ScannerName == ScannerSource {
			rapid7Scans = append(rapid7Scans, scan)
		}
	}
	logging.Logger.Infof("Filtered scans to %s source, returning %d scans", ScannerSource, len(rapid7Scans))
	return rapid7Scans, nil
}

func (tf *API) GetAppByName(teamName string, appName string) (Application, error) {
	var endpoint = fmt.Sprintf("rest/applications/%s/lookup?name=%s", teamName, appName)
	var header = tf.FormatHeader()
	var url = tf.FormatUrl(endpoint)
	var app Application
	var method = shared.ApiMethodGet

	var response, err = tf.APIClient.CallAPI(url, method, nil, header)

	if err != nil {
		log.Error("Error in threadfix/GetAppByName", err)
		return app, errors.New("error in threadfix/GetAppByName")
	}
	json.Unmarshal(response.Body(), &app)
	return app, nil
}

func (tf *API) FormatUrl(endpoint string) string {
	var fullUrl = tf.Config.Host + ":" + tf.Config.Port + "/threadfix/" + endpoint
	return fullUrl
}

func (tf *API) FormatHeader() map[string]string {
	var header = make(map[string]string)
	header["Authorization"] = "APIKEY " + tf.Config.APIKey
	header["Accept"] = "application/json"

	return header
}

func (tf *API) ListSeverities() (ListSeveritiesResponse, error) {
	var endpoint = "rest/latest/severities"
	var header = tf.FormatHeader()
	var url = tf.FormatUrl(endpoint)
	var severities ListSeveritiesResponse
	var method = shared.ApiMethodGet

	var response, err = tf.APIClient.CallAPI(url, method, nil, header)

	if err != nil {
		log.Error("Error in threadfix/ListSeverities", err)
		return severities, errors.New("error in threadfix/ListSeverities")
	}
	json.Unmarshal(response.Body(), &severities)
	return severities, nil
}
