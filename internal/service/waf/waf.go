package service_waf

import (
	"log"
	"os"
	"strings"
	"sync/atomic"

	"github.com/corazawaf/libinjection-go"
	"github.com/jahrulnr/go-waf/config"
	"github.com/jahrulnr/go-waf/internal/interface/service"
	"github.com/jahrulnr/go-waf/pkg/logger"
	"gopkg.in/yaml.v2"
)

type WAFService struct {
	config *config.Config

	commandInjectionKeywords []string
	pathTraversalKeywords    []string
	sensitivePathKeywords    []string
	knownWebshellKeywords    []string
	scannerUserAgentKeywords []string
}

func NewWAFService(config *config.Config, keywordsFile string) service.WAFInterface {
	keywords := loadKeywords(keywordsFile)

	return &WAFService{
		config: config,

		commandInjectionKeywords: keywords.CommandInjectionKeywords,
		pathTraversalKeywords:    keywords.PathTraversalKeywords,
		sensitivePathKeywords:    keywords.SensitivePathKeywords,
		knownWebshellKeywords:    keywords.KnownWebshellKeywords,
		scannerUserAgentKeywords: keywords.ScannerUserAgentKeywords,
	}
}

func loadKeywords(filename string) service.Keywords {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("error reading keywords file: %v", err)
	}

	var keywords service.Keywords
	err = yaml.Unmarshal(data, &keywords)
	if err != nil {
		log.Fatalf("error unmarshalling keywords: %v", err)
	}

	return keywords
}

func (w *WAFService) HandleRequest(request *service.Request) (*service.Response, error) {
	var headerThreat, bodyThreat atomic.Bool

	if w.config.WAF_PROTECT_HEADER {
		headerThreat.Store(w.DetectHeaderThreats(request))
	}

	if w.config.WAF_PROTECT_BODY {
		bodyThreat.Store(w.DetectBodyThreats(request))
	}

	if headerThreat.Load() || bodyThreat.Load() {
		return &service.Response{StatusCode: 403, Body: []byte("Threat Detected")}, nil
	}

	return nil, nil
}

func (w *WAFService) DetectHeaderThreats(request *service.Request) bool {
	if matched, rule := w.detectPathThreats(request.Path); matched {
		w.logThreat(request, "path", rule)
		return true
	}

	if ua := request.Headers["User-Agent"]; ua != "" {
		if matched, rule := matchKeywordFold(ua, w.scannerUserAgentKeywords); matched {
			w.logThreat(request, "scanner_user_agent", rule)
			return true
		}
	}

	for _, value := range request.Headers {
		if injection, _ := libinjection.IsSQLi(value); injection {
			w.logThreat(request, "sqli", value)
			return true
		}
	}

	for _, value := range request.Headers {
		if libinjection.IsXSS(value) {
			w.logThreat(request, "xss", value)
			return true
		}
	}

	for _, keywords := range [][]string{
		w.commandInjectionKeywords,
		w.pathTraversalKeywords,
		w.sensitivePathKeywords,
		w.knownWebshellKeywords,
	} {
		for _, value := range request.Headers {
			if matched, rule := matchKeyword(value, keywords); matched {
				w.logThreat(request, "keyword", rule)
				return true
			}
		}
	}

	return false
}

func (w *WAFService) DetectBodyThreats(request *service.Request) bool {
	body := string(request.Body)

	if injection, _ := libinjection.IsSQLi(body); injection {
		w.logThreat(request, "sqli_body", body)
		return true
	}

	if libinjection.IsXSS(body) {
		w.logThreat(request, "xss_body", body)
		return true
	}

	for _, keywords := range [][]string{
		w.commandInjectionKeywords,
		w.pathTraversalKeywords,
		w.sensitivePathKeywords,
		w.knownWebshellKeywords,
	} {
		if matched, rule := matchKeyword(body, keywords); matched {
			w.logThreat(request, "keyword_body", rule)
			return true
		}
	}

	return false
}

func (w *WAFService) detectPathThreats(path string) (bool, string) {
	if matched, rule := matchKeywordFold(path, w.sensitivePathKeywords); matched {
		return true, rule
	}

	if matched, rule := matchKeywordFold(path, w.knownWebshellKeywords); matched {
		return true, rule
	}

	return false, ""
}

func matchKeyword(text string, patterns []string) (bool, string) {
	for _, pattern := range patterns {
		if pattern != "" && strings.Contains(text, pattern) {
			return true, pattern
		}
	}

	return false, ""
}

func matchKeywordFold(text string, patterns []string) (bool, string) {
	lowerText := strings.ToLower(text)
	for _, pattern := range patterns {
		if pattern != "" && strings.Contains(lowerText, strings.ToLower(pattern)) {
			return true, pattern
		}
	}

	return false, ""
}

func (w *WAFService) logThreat(request *service.Request, kind, detail string) {
	logger.Logger("WAF block", kind, request.IP, request.Path, detail).Warn()
}
