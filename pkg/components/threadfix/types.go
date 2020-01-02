package threadfix

type UploadScanResponse struct {
	Message       string `json:"message"`
	Success       bool   `json:"success"`
	ResponseCode  int    `json:"responseCode"`
	UploadMessage string `json:"object"`
	Links         Links  `json:"links"`
}

type Links []struct {
	Method string `json:"method"`
	Rel    string `json:"rel"`
	Href   string `json:"href"`
}

type ScanMetadata struct {
	ID          int    `json:"id"`
	ImportTime  int    `json:"importTime"`
	UpdatedDate int    `json:"updatedDate"`
	ScannerName string `json:"scannerName"`
}

type ListScansResponse struct {
	Message      string         `json:"message"`
	Success      bool           `json:"success"`
	ResponseCode int            `json:"responseCode"`
	ScanMetadata []ScanMetadata `json:"object"`
}

// Currently blank because Threadfix has always returned a blank PolicyStatus thus far
type PolicyStatus []struct {
}

type ScanStats struct {
	ID                              int    `json:"id"`
	ImportTime                      int    `json:"importTime"`
	UpdatedDate                     int    `json:"updatedDate"`
	NumberClosedVulnerabilities     int    `json:"numberClosedVulnerabilities"`
	NumberNewVulnerabilities        int    `json:"numberNewVulnerabilities"`
	NumberOldVulnerabilities        int    `json:"numberOldVulnerabilities"`
	NumberResurfacedVulnerabilities int    `json:"numberResurfacedVulnerabilities"`
	NumberTotalVulnerabilities      int    `json:"numberTotalVulnerabilities"`
	NumberRepeatResults             int    `json:"numberRepeatResults"`
	NumberRepeatFindings            int    `json:"numberRepeatFindings"`
	NumberInfoVulnerabilities       int    `json:"numberInfoVulnerabilities"`
	NumberLowVulnerabilities        int    `json:"numberLowVulnerabilities"`
	NumberMediumVulnerabilities     int    `json:"numberMediumVulnerabilities"`
	NumberHighVulnerabilities       int    `json:"numberHighVulnerabilities"`
	NumberCriticalVulnerabilities   int    `json:"numberCriticalVulnerabilities"`
	ScannerName                     string `json:"scannerName"`
}

type AppData struct {
	ID                     int    `json:"id"`
	Name                   string `json:"name"`
	URL                    string `json:"url"`
	UniqueID               string `json:"uniqueId,omitempty"`
	ApplicationCriticality struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"applicationCriticality"`
	PolicyStatuses    PolicyStatus `json:"policyStatuses"`
	Description       string       `json:"description,omitempty"`
	ReleaseFrequency  string       `json:"releaseFrequency"`
	TestEnvironment   string       `json:"testEnvironment,omitempty"`
	GrcApplication    string       `json:"grcApplication,omitempty"`
	ScanStats         []ScanStats  `json:"scans"`
	InfoVulnCount     int          `json:"infoVulnCount"`
	LowVulnCount      int          `json:"lowVulnCount"`
	MediumVulnCount   int          `json:"mediumVulnCount"`
	HighVulnCount     int          `json:"highVulnCount"`
	CriticalVulnCount int          `json:"criticalVulnCount"`
	TotalVulnCount    int          `json:"totalVulnCount"`
	IsInternal        bool         `json:"isInternal"`
	WAF               string       `json:"waf,omitempty"`
	Organization      struct {
		Name string `json:"name"`
		ID   int    `json:"id"`
	} `json:"organization"`
}

type Application struct {
	Message      string  `json:"message"`
	Success      bool    `json:"success"`
	ResponseCode int     `json:"responseCode"`
	AppData      AppData `json:"object"`
}

// Structs for Threadfix Scan file
type SurfaceLocation struct {
	URL            string `json:"url"`
	Parameter      string `json:"parameter"`
	AttackString   string `json:"attackString,omitempty"`
	AttackRequest  string `json:"attackRequest,omitempty"`
	AttackResponse string `json:"attackResponse,omitempty"`
}

type Mapping struct {
	MappingType     string `json:"mappingType"`
	Value           string `json:"value"`
	Primary         bool   `json:"primary"`
	VendorOtherType string `json:"vendorOtherType,omitempty"`
}

type DynamicDetails struct {
	SurfaceLocation SurfaceLocation `json:"surfaceLocation"`
}

type Finding struct {
	NativeID              string            `json:"nativeId"`
	Severity              string            `json:"severity"`
	NativeSeverity        string            `json:"nativeSeverity"`
	Summary               string            `json:"summary"`
	Description           string            `json:"description"`
	ScannerDetail         string            `json:"scannerDetail"`
	ScannerRecommendation string            `json:"scannerRecommendation"`
	DynamicDetails        DynamicDetails    `json:"dynamicDetails"`
	Metadata              map[string]string `json:"metadata,omitempty"`
	Mappings              []Mapping         `json:"mappings"`
	Comments              []string          `json:"comments"`
}

type ThreadfixScan struct {
	Created          string            `json:"created"`
	Updated          string            `json:"updated"`
	Exported         string            `json:"exported,omitempty"`
	CollectionType   string            `json:"collectionType"`
	Source           string            `json:"source"`
	ExecutiveSummary string            `json:"executiveSummary"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	Findings         []Finding         `json:"findings"`
}

type ListSeveritiesResponse struct {
	Message            string                  `json:"message"`
	Success            bool                    `json:"success"`
	ResponseCode       int                     `json:"responseCode"`
	SeveritiesMetadata []VulnerabilitySeverity `json:"object"`
}

type VulnerabilitySeverity struct {
	Id          int    `json:"id"`
	Name        string `json:"name"`
	IntValue    int    `json:"intValue"`
	CustomName  string `json:"customName"`
	DisplayName string `json:"displayName"`
}

type ThreadfixConfiguration struct {
	APIKey   string
	Host     string
	Port     string
}
