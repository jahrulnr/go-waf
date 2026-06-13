package service

type Request struct {
	IP      string
	Path    string
	Headers map[string]string
	Body    []byte
}

type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

type Keywords struct {
	CommandInjectionKeywords []string `yaml:"command_injection"`
	PathTraversalKeywords    []string `yaml:"path_traversal"`
	SensitivePathKeywords    []string `yaml:"sensitive_paths"`
	KnownWebshellKeywords    []string `yaml:"known_webshells"`
	ScannerUserAgentKeywords []string `yaml:"scanner_user_agents"`
}

type WAFInterface interface {
	HandleRequest(request *Request) (*Response, error)
	DetectHeaderThreats(request *Request) bool
	DetectBodyThreats(request *Request) bool
}
