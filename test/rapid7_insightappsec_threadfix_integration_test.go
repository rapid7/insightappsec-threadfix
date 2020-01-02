package test

import (
	"encoding/json"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/components/insightappsec"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/integration"
	"github.com/rapid7/strategic-integrations/appsec/rapid7-insightappsec-threadfix/pkg/shared"
	"os"
	"testing"
)

func init() {
	var iasClient insightappsec.API

	var config = insightappsec.InsightAppSecConfiguration{
		Region:   "us",
		APIKey:   os.Getenv("INSIGHTAPPSEC_API_KEY"),
		BasePath: "https://%s.api.insight.rapid7.com/ias/v1/"}

	var apiConfig = shared.APIConfiguration{Timeout: 30, RestyClient: resty.New()}
	var apiClient = shared.APIClient{Config: apiConfig}

	iasClient = insightappsec.API{Config: config, APIClient: apiClient}

	// Inject InsightAppSec Client due to need of fetching modules/attack documentation
	integration.IasClient = iasClient

	// Set up Severity Mapping
	var severityMappings = []integration.SeverityMapping{
		{Threadfix: "SAFE", InsightAppSec: "Info",},
		{Threadfix: "INFORMATIONAL", InsightAppSec: "Low",},
		{Threadfix: "LOW", InsightAppSec: "Medium",},
		{Threadfix: "MEDIUM", InsightAppSec: "High",},
		{Threadfix: "HIGH", InsightAppSec: "Critical",},
	}
	// Inject Severity Mappings that is usually provided by configuration
	integration.SeverityMappings = severityMappings
}

func TestConvertScan(t *testing.T) {
	rawScan := `{
            "id": "3113af46-29cb-4f93-92e5-eddfbac4ed2c",
            "app": {
                "id": "1550c422-2273-4f27-9674-31fc814f3558"
            },
            "scan_config": {
                "id": "5b00b027-9a3d-402a-8f12-86bb761a19e6"
            },
            "submitter": {
                "type": "ORGANIZATION"
            },
            "submit_time": "2019-08-05T18:10:17.189",
            "completion_time": "2019-08-05T18:13:56.913",
            "status": "COMPLETE",
            "links": [
                {
                    "rel": "self",
                    "href": "https://us.api.insight.rapid7.com:443/ias/v1/search/3113af46-29cb-4f93-92e5-eddfbac4ed2c"
                }
            ]
        }`
	scan := &insightappsec.Scan{}
	json.Unmarshal([]byte(rawScan), scan)

	rawVulnerabilities := `[
        {
            "id": "fa7adfb4-81e9-46a1-b55b-732c4d4b474d",
            "app": {
                "id": "1550c422-2273-4f27-9674-31fc814f3558"
            },
            "root_cause": {
                "url": "http://webscantest.com/datastore/search_by_id.php",
                "parameter": "id",
                "method": "POST"
            },
            "severity": "HIGH",
            "status": "UNREVIEWED",
            "variances": [
                {
                    "original_value": "x7rij77p",
                    "original_exchange": {
                        "request": "POST /datastore/search_by_id.php HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nContent-Length: 11\r\nReferer: http://webscantest.com/datastore/search_by_id.php\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\nid=x7rij77p",
                        "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:52:37 GMT\r\nPragma: no-cache\r\nContent-Length: 718\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nVary: Accept-Encoding\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                    },
                    "module": {
                        "id": "b6f559d3-74b5-451e-b424-a1c1fb264fa6"
                    },
                    "attack": {
                        "id": "DBI03"
                    },
                    "attack_value": "x7rij77p\"",
                    "attack_exchanges": [
                        {
                            "request": "POST /datastore/search_by_id.php HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nContent-Length: 12\r\nReferer: http://webscantest.com/datastore/search_by_id.php\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: last_search=HTTP%3A%2F%2Fappspidered.rapid7.com%2Fxss%2Fscript%2F0f40b8ddd1ccc35d4f9df6717053568fbbfdc2df; TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\nid=x7rij77p\"",
                            "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:53:12 GMT\r\nPragma: no-cache\r\nContent-Length: 786\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nVary: Accept-Encoding\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                        }
                    ]
                },
                {
                    "original_value": "x7rij77p",
                    "original_exchange": {
                        "request": "POST /datastore/search_by_id.php HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nContent-Length: 11\r\nReferer: http://webscantest.com/datastore/search_by_id.php\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\nid=x7rij77p",
                        "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:52:37 GMT\r\nPragma: no-cache\r\nContent-Length: 718\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nVary: Accept-Encoding\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                    },
                    "module": {
                        "id": "b6f559d3-74b5-451e-b424-a1c1fb264fa6"
                    },
                    "attack": {
                        "id": "DBI01"
                    },
                    "attack_value": "'x7rij77p",
                    "attack_exchanges": [
                        {
                            "request": "POST /datastore/search_by_id.php HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nContent-Length: 12\r\nReferer: http://webscantest.com/datastore/search_by_id.php\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: last_search=HTTP%3A%2F%2Fappspidered.rapid7.com%2Fxss%2Fscript%2F2f1fae9e5a5b81e7d1a77a369d80b4f45ebb946e; TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\nid='x7rij77p",
                            "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:53:12 GMT\r\nPragma: no-cache\r\nContent-Length: 783\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nVary: Accept-Encoding\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                        }
                    ]
                },
                {
                    "original_value": "x7rij77p",
                    "original_exchange": {
                        "request": "POST /datastore/search_by_id.php HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nContent-Length: 11\r\nReferer: http://webscantest.com/datastore/search_by_id.php\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\nid=x7rij77p",
                        "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:52:37 GMT\r\nPragma: no-cache\r\nContent-Length: 718\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nVary: Accept-Encoding\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                    },
                    "module": {
                        "id": "b6f559d3-74b5-451e-b424-a1c1fb264fa6"
                    },
                    "attack": {
                        "id": "DBI02"
                    },
                    "attack_value": "x7rij77p'",
                    "attack_exchanges": [
                        {
                            "request": "POST /datastore/search_by_id.php HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nContent-Length: 12\r\nReferer: http://webscantest.com/datastore/search_by_id.php\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: last_search=HTTP%3A%2F%2Fappspidered.rapid7.com%2Fxss%2Fscript%2F2f1fae9e5a5b81e7d1a77a369d80b4f45ebb946e; TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\nid=x7rij77p'",
                            "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:53:12 GMT\r\nPragma: no-cache\r\nContent-Length: 782\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nVary: Accept-Encoding\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                        }
                    ]
                }
            ],
            "links": [
                {
                    "rel": "self",
                    "href": "https://us.api.insight.rapid7.com:443/ias/v1/search/fa7adfb4-81e9-46a1-b55b-732c4d4b474d"
                }
            ]
        },
        {
            "id": "35d39455-0333-4e68-9baa-e77d2a793cb4",
            "app": {
                "id": "1550c422-2273-4f27-9674-31fc814f3558"
            },
            "root_cause": {
                "url": "http://webscantest.com/datastore/getimage_by_name.php",
                "parameter": "name",
                "method": "GET"
            },
            "severity": "HIGH",
            "status": "UNREVIEWED",
            "variances": [
                {
                    "original_value": "Rake",
                    "original_exchange": {
                        "request": "GET /datastore/getimage_by_name.php?name=Rake HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nReferer: http://webscantest.com/datastore/search_get_by_name.php?name=Rake\r\nCookie: TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\n",
                        "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:52:38 GMT\r\nPragma: no-cache\r\nContent-Length: 795\r\nContent-Type: image/jpeg\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                    },
                    "module": {
                        "id": "b6f559d3-74b5-451e-b424-a1c1fb264fa6"
                    },
                    "attack": {
                        "id": "DBI01"
                    },
                    "attack_value": "'Rake",
                    "attack_exchanges": [
                        {
                            "request": "GET /datastore/getimage_by_name.php?name='Rake HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nReferer: http://webscantest.com/datastore/search_get_by_name.php?name=Rake\r\nCookie: last_search=3; TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\n",
                            "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:52:42 GMT\r\nPragma: no-cache\r\nContent-Length: 209\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nVary: Accept-Encoding\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                        }
                    ]
                },
                {
                    "original_value": "Rake",
                    "original_exchange": {
                        "request": "GET /datastore/getimage_by_name.php?name=Rake HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nReferer: http://webscantest.com/datastore/search_get_by_name.php?name=Rake\r\nCookie: TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\n",
                        "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:52:38 GMT\r\nPragma: no-cache\r\nContent-Length: 795\r\nContent-Type: image/jpeg\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                    },
                    "module": {
                        "id": "b6f559d3-74b5-451e-b424-a1c1fb264fa6"
                    },
                    "attack": {
                        "id": "DBI05"
                    },
                    "attack_value": "Rake%25%27",
                    "attack_exchanges": [
                        {
                            "request": "GET /datastore/getimage_by_name.php?name=Rake%25%27 HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nReferer: http://webscantest.com/datastore/search_get_by_name.php?name=Rake\r\nCookie: last_search=3; TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\n",
                            "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:53:09 GMT\r\nPragma: no-cache\r\nContent-Length: 212\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nVary: Accept-Encoding\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                        }
                    ]
                },
                {
                    "original_value": "Rake",
                    "original_exchange": {
                        "request": "GET /datastore/getimage_by_name.php?name=Rake HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nReferer: http://webscantest.com/datastore/search_get_by_name.php?name=Rake\r\nCookie: TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\n",
                        "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:52:38 GMT\r\nPragma: no-cache\r\nContent-Length: 795\r\nContent-Type: image/jpeg\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                    },
                    "module": {
                        "id": "b6f559d3-74b5-451e-b424-a1c1fb264fa6"
                    },
                    "attack": {
                        "id": "DBI02"
                    },
                    "attack_value": "Rake'",
                    "attack_exchanges": [
                        {
                            "request": "GET /datastore/getimage_by_name.php?name=Rake' HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168Safari/535.19\r\nHost: webscantest.com\r\nReferer: http://webscantest.com/datastore/search_get_by_name.php?name=Rake\r\nCookie: last_search=3; TEST_SESSIONID=4qtskinbbt4mvrd8sbah8gogv6; NB_SRVID=srv140700\r\n\r\n",
                            "response": "HTTP/1.1 200 OK\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nConnection: close\r\nDate: Thu, 08 Aug 2019 20:52:42 GMT\r\nPragma: no-cache\r\nContent-Length: 210\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nVary: Accept-Encoding\r\nX-Powered-By: PHP/5.5.9-1ubuntu4.29"
                        }
                    ]
                }
            ],
            "links": [
                {
                    "rel": "self",
                    "href": "https://us.api.insight.rapid7.com:443/ias/v1/search/35d39455-0333-4e68-9baa-e77d2a793cb4"
                }
            ]
        }
    ]`
	vulnerabilities := &[]insightappsec.Vulnerability{}
	json.Unmarshal([]byte(rawVulnerabilities), vulnerabilities)

	var threadfixScan = integration.ConvertScan(*scan, *vulnerabilities)

	if len(threadfixScan.Findings) == 2 {
		fmt.Println("Matched same number of findings pre/post conversion")
	} else {
		t.Error("Number of findings mismatch after converting scan")
	}
}
