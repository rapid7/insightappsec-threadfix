package insightappsec

type Links []struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type Metadata struct {
	Index      int `json:"index"`
	Size       int `json:"size"`
	TotalData  int `json:"total_data"`
	TotalPages int `json:"total_pages"`
}

type App struct {
	ID string `json:"id"`
}

type RootCause struct {
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Method    string `json:"method"`
}

type Variance struct {
	OriginalValue    string `json:"original_value"`
	OriginalExchange struct {
		Request  string `json:"request"`
		Response string `json:"response"`
	} `json:"original_exchange"`
	Module struct {
		ID string `json:"id"`
	} `json:"module"`
	Attack struct {
		ID string `json:"id"`
	} `json:"attack"`
	AttackValue     string `json:"attack_value"`
	AttackExchanges []struct {
		Request  string `json:"request"`
		Response string `json:"response"`
	} `json:"attack_exchanges"`
}

type Vulnerability struct {
	ID        string     `json:"id"`
	App       App        `json:"app"`
	RootCause RootCause  `json:"root_cause,omitempty"`
	Severity  string     `json:"severity"`
	Status    string     `json:"status"`
	Variances []Variance `json:"variances"`
	Links     Links      `json:"links"`
}

type VulnerabilitySearchResponse struct {
	Data     []Vulnerability `json:"data"`
	Metadata Metadata        `json:"metadata"`
	Links    Links           `json:"links"`
}

type Scan struct {
	ID  string `json:"id"`
	App struct {
		ID string `json:"id"`
	} `json:"app"`
	ScanConfig struct {
		ID string `json:"id"`
	} `json:"scan_config"`
	Submitter struct {
		Type string `json:"type"`
	} `json:"submitter"`
	SubmitTime     string `json:"submit_time"`
	CompletionTime string `json:"completion_time"`
	Status         string `json:"status"`
	FailureReason  string `json:"failure_reason,omitempty"`
	Links          Links  `json:"links"`
}

type ScanSearchResponse struct {
	Data     []Scan   `json:"data"`
	Metadata Metadata `json:"metadata"`
	Links    Links    `json:"links"`
}

type SearchParameters struct {
	Type  string `json:"type"`
	Query string `json:"query"`
}

type Application struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Links       Links  `json:"links"`
}

type AppSearchResponse struct {
	Data     []Application `json:"data"`
	Metadata Metadata      `json:"metadata"`
	Links    Links         `json:"links"`
}

type Module struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AttackDocumentation struct {
	References     map[string]string `json:"references"`
	Description    string            `json:"description,omitempty"`
	Recommendation string            `json:"recommendation,omitempty"`
}

type Url struct {
	Endpoint string `json:"endpoint"`
	Index    int    `json:"index,omitempty"`
	Size     int    `json:"size,omitempty"`
	Sort     string `json:"sort,omitempty"`
}

type ScanConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	App         struct {
		ID string `json:"id"`
	} `json:"app"`
	AttackTemplate struct {
		ID string `json:"id"`
	} `json:"attack_template"`
	Assignment struct {
		Type        string `json:"type"`
		Environment string `json:"environment"`
	} `json:"assignment"`
	Links Links `json:"links"`
}

type ScanConfigResponse struct {
	Data     []ScanConfig `json:"data"`
	Metadata Metadata     `json:"metadata"`
	Links    Links        `json:"links"`
}

type InsightAppSecConfiguration struct {
	Region   string
	APIKey   string
	BasePath string
}
