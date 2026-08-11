package template_options

import "testing"

func TestNew(t *testing.T) {
	t.Parallel()

	options := New(nil)
	if options == nil {
		t.Fatalf("nil options")
	}

	if options.AuthenticationMode != AuthenticationModeCookie {
		t.Errorf("authentication mode: got %q", options.AuthenticationMode)
	}
	if options.CseClientPublicJwkHeader != DefaultCseClientPublicJwkHeader {
		t.Errorf("cse client public jwk header: got %q", options.CseClientPublicJwkHeader)
	}
	if options.CseContentEncryption != DefaultCseContentEncryption {
		t.Errorf("cse content encryption: got %q", options.CseContentEncryption)
	}
	if options.CseKeyAlgorithm != DefaultCseKeyAlgorithm {
		t.Errorf("cse key algorithm: got %q", options.CseKeyAlgorithm)
	}
	if options.CseKeyAlgorithmCurve != DefaultCseKeyAlgorithmCurve {
		t.Errorf("cse key algorithm curve: got %q", options.CseKeyAlgorithmCurve)
	}
	if options.AcceptBaseUrlArgument {
		t.Errorf("expected accept base url argument to default to false")
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		option Option
		check  func(t *testing.T, options *Options)
	}{
		{
			name:   "with authentication mode",
			option: WithAuthenticationMode(AuthenticationModeBearer),
			check: func(t *testing.T, options *Options) {
				if options.AuthenticationMode != AuthenticationModeBearer {
					t.Errorf("authentication mode: got %q", options.AuthenticationMode)
				}
			},
		},
		{
			name:   "with cse client public jwk header",
			option: WithCseClientPublicJwkHeader("X-Test"),
			check: func(t *testing.T, options *Options) {
				if options.CseClientPublicJwkHeader != "X-Test" {
					t.Errorf("cse client public jwk header: got %q", options.CseClientPublicJwkHeader)
				}
			},
		},
		{
			name:   "with cse content encryption",
			option: WithCseContentEncryption("A128GCM"),
			check: func(t *testing.T, options *Options) {
				if options.CseContentEncryption != "A128GCM" {
					t.Errorf("cse content encryption: got %q", options.CseContentEncryption)
				}
			},
		},
		{
			name:   "with cse key algorithm",
			option: WithCseKeyAlgorithm("ECDH-ES+A256KW"),
			check: func(t *testing.T, options *Options) {
				if options.CseKeyAlgorithm != "ECDH-ES+A256KW" {
					t.Errorf("cse key algorithm: got %q", options.CseKeyAlgorithm)
				}
			},
		},
		{
			name:   "with cse key algorithm curve",
			option: WithCseKeyAlgorithmCurve("P-384"),
			check: func(t *testing.T, options *Options) {
				if options.CseKeyAlgorithmCurve != "P-384" {
					t.Errorf("cse key algorithm curve: got %q", options.CseKeyAlgorithmCurve)
				}
			},
		},
		{
			name:   "with accept base url argument",
			option: WithAcceptBaseUrlArgument(true),
			check: func(t *testing.T, options *Options) {
				if !options.AcceptBaseUrlArgument {
					t.Errorf("expected accept base url argument")
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
