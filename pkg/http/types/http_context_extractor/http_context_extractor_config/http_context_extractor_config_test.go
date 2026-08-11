package http_context_extractor_config

import (
	"testing"

	"github.com/Motmedel/utils_go/pkg/schema"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New(nil)
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.ReplaceableMessages != nil || config.MaskedUrlParams != nil || config.MaskedHeaders != nil ||
		config.MaskedRequestBodyUrls != nil || config.MaskedResponseBodyUrls != nil {
		t.Errorf("expected zero config, got %+v", config)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	urlPattern := &schema.Url{Path: "/api/secret"}

	testCases := []struct {
		name   string
		option Option
		check  func(t *testing.T, config *Config)
	}{
		{
			name:   "with replaceable messages",
			option: WithReplaceableMessages("message-a", "message-b"),
			check: func(t *testing.T, config *Config) {
				if len(config.ReplaceableMessages) != 2 || config.ReplaceableMessages[0] != "message-a" {
					t.Errorf("replaceable messages: got %v", config.ReplaceableMessages)
				}
			},
		},
		{
			name:   "with masked url params",
			option: WithMaskedUrlParams(urlPattern),
			check: func(t *testing.T, config *Config) {
				if len(config.MaskedUrlParams) != 1 || config.MaskedUrlParams[0] != urlPattern {
					t.Errorf("masked url params: got %v", config.MaskedUrlParams)
				}
			},
		},
		{
			name:   "with masked headers",
			option: WithMaskedHeaders(&MaskedHeader{Url: urlPattern, Headers: []string{"X-Secret"}}),
			check: func(t *testing.T, config *Config) {
				if len(config.MaskedHeaders) != 1 || config.MaskedHeaders[0].Headers[0] != "X-Secret" {
					t.Errorf("masked headers: got %v", config.MaskedHeaders)
				}
			},
		},
		{
			name:   "with masked request body urls",
			option: WithMaskedRequestBodyUrls(urlPattern),
			check: func(t *testing.T, config *Config) {
				if len(config.MaskedRequestBodyUrls) != 1 || config.MaskedRequestBodyUrls[0] != urlPattern {
					t.Errorf("masked request body urls: got %v", config.MaskedRequestBodyUrls)
				}
			},
		},
		{
			name:   "with masked response body urls",
			option: WithMaskedResponseBodyUrls(urlPattern),
			check: func(t *testing.T, config *Config) {
				if len(config.MaskedResponseBodyUrls) != 1 || config.MaskedResponseBodyUrls[0] != urlPattern {
					t.Errorf("masked response body urls: got %v", config.MaskedResponseBodyUrls)
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testCase.check(t, New(testCase.option))
		})
	}
}
