package shared

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"strings"
	"time"
)

type APIConfiguration struct {
	Timeout     int
	RestyClient *resty.Client
}


type APIClient struct {
	Config APIConfiguration
}

func (apiClient *APIClient) CallAPI(path string, method string,
	postBody interface{},
	headerParams map[string]string) (*resty.Response, error) {

	apiClient.prepareClient()
	request := apiClient.prepareRequest(apiClient.Config.RestyClient, postBody, headerParams)

	switch strings.ToUpper(method) {
	case "GET":
		response, err := request.Get(path)
		return response, err
	case "POST":
		response, err := request.Post(path)
		return response, err
	case "PUT":
		response, err := request.Put(path)
		return response, err
	case "PATCH":
		response, err := request.Patch(path)
		return response, err
	case "DELETE":
		response, err := request.Delete(path)
		return response, err
	}

	return nil, fmt.Errorf("invalid method %v", method)
}

func (apiClient *APIClient) prepareClient() {
	var timeout = apiClient.Config.Timeout
	apiClient.Config.RestyClient.SetTimeout(time.Duration(timeout) * time.Second)
}

func (apiClient *APIClient) prepareRequest(
	rClient *resty.Client,
	postBody interface{},
	headerParams map[string]string) *resty.Request {

	request := rClient.R()
	request.SetBody(postBody)

	if len(headerParams) > 0 {
		request.SetHeaders(headerParams)
	}
	return request
}
