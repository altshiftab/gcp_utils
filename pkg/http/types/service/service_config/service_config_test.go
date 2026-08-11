package service_config

import (
	"testing"

	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New(nil)
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.Public || config.StaticContentEndpoints != nil || config.Redirects != nil {
		t.Errorf("expected zero config, got %+v", config)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	endpoints := []*endpoint.Endpoint{{Path: "/static"}}
	redirects := [][2]string{{"www.example.com", "example.com"}}

	testCases := []struct {
		name   string
		option Option
		check  func(t *testing.T, config *Config)
	}{
		{
			name:   "with public",
			option: WithPublic(true),
			check: func(t *testing.T, config *Config) {
				if !config.Public {
					t.Errorf("expected public")
				}
			},
		},
		{
			name:   "with static content endpoints",
			option: WithStaticContentEndpoints(endpoints),
			check: func(t *testing.T, config *Config) {
				if len(config.StaticContentEndpoints) != 1 || config.StaticContentEndpoints[0].Path != "/static" {
					t.Errorf("static content endpoints: got %+v", config.StaticContentEndpoints)
				}
			},
		},
		{
			name:   "with redirects",
			option: WithRedirects(redirects),
			check: func(t *testing.T, config *Config) {
				if len(config.Redirects) != 1 || config.Redirects[0] != [2]string{"www.example.com", "example.com"} {
					t.Errorf("redirects: got %+v", config.Redirects)
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
