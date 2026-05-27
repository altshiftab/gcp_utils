package generate_endpoint_config

import (
	"fmt"
	"net/mail"
	"net/url"
	"time"

	"github.com/Motmedel/utils_go/pkg/mail/types/message"
	motmedelUuid "github.com/Motmedel/utils_go/pkg/uuid"
)

var (
	DefaultPath           = "/api/login/magic/generate"
	DefaultLinkExpiration = 15 * time.Minute
	DefaultSubject        = "Sign in"
	DefaultMaxBytes int64 = 512
	DefaultMessageBuilder = func(toAddress *mail.Address, linkUrl *url.URL, expiresAt time.Time) (*message.Body, error) {
		content := fmt.Sprintf(
			"Click the link below to sign in. The link expires at %s.\r\n\r\n%s\r\n\r\nIf you did not request this email, you can safely ignore it.\r\n",
			expiresAt.UTC().Format(time.RFC1123),
			linkUrl.String(),
		)
		return &message.Body{Content: []byte(content), ContentType: "text/plain; charset=utf-8"}, nil
	}
	DefaultMakeNonce = motmedelUuid.NewString
)

type MessageBuilder func(toAddress *mail.Address, linkUrl *url.URL, expiresAt time.Time) (*message.Body, error)

type Config struct {
	Path             string
	LinkExpiration   time.Duration
	Subject          string
	MaxBytes         int64
	MessageBuilder   MessageBuilder
	MakeNonce        func() string
	ReplyToAddresses []*mail.Address
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path:           DefaultPath,
		LinkExpiration: DefaultLinkExpiration,
		Subject:        DefaultSubject,
		MaxBytes:       DefaultMaxBytes,
		MessageBuilder: DefaultMessageBuilder,
		MakeNonce:      DefaultMakeNonce,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithPath(path string) Option {
	return func(config *Config) {
		config.Path = path
	}
}

func WithLinkExpiration(linkExpiration time.Duration) Option {
	return func(config *Config) {
		config.LinkExpiration = linkExpiration
	}
}

func WithSubject(subject string) Option {
	return func(config *Config) {
		config.Subject = subject
	}
}

func WithMaxBytes(maxBytes int64) Option {
	return func(config *Config) {
		config.MaxBytes = maxBytes
	}
}

func WithMessageBuilder(messageBuilder MessageBuilder) Option {
	return func(config *Config) {
		config.MessageBuilder = messageBuilder
	}
}

func WithMakeNonce(makeNonce func() string) Option {
	return func(config *Config) {
		config.MakeNonce = makeNonce
	}
}

func WithReplyToAddresses(replyToAddresses []*mail.Address) Option {
	return func(config *Config) {
		config.ReplyToAddresses = replyToAddresses
	}
}
