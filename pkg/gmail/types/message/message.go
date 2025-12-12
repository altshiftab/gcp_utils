package message

import (
	"crypto/rand"
	"fmt"
	"net/mail"
	"strings"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	mailAddressValidation "github.com/Motmedel/utils_go/pkg/mail/validation/address"
	gmailErrors "github.com/altshiftab/gcp_utils/pkg/gmail/errors"
)

type Option func(*Message)

type Body struct {
	Content     []byte
	ContentType string
}

type Message struct {
	From     string
	To       string
	Subject  string
	Body     *Body
	FromName string
	ReplyTo  string
	Domain   string
}

func (message *Message) String() (string, error) {
	var builder strings.Builder
	timeNow := time.Now()

	fromMailAddress := mail.Address{Address: message.From}
	if fromName := message.FromName; fromName != "" {
		fromMailAddress.Name = fromName
	}

	builder.WriteString(fmt.Sprintf("From: %s\r\n", fromMailAddress.String()))
	builder.WriteString(fmt.Sprintf("To: %s\r\n", message.To))
	if replyTo := message.ReplyTo; replyTo != "" {
		builder.WriteString(fmt.Sprintf("Reply-To: %s\r\n", replyTo))
	}
	builder.WriteString(fmt.Sprintf("Subject: %s\r\n", message.Subject))
	builder.WriteString(fmt.Sprintf("Date: %s\r\n", timeNow.Format(time.RFC1123Z)))

	domain := message.Domain
	if domain == "" {
		fromAddress := fromMailAddress.Address
		if at := strings.LastIndex(fromAddress, "@"); at != -1 && at+1 < len(fromAddress) {
			domain = fromMailAddress.Address[at+1:]
		} else {
			return "", motmedelErrors.NewWithTrace(gmailErrors.ErrBadFromAddress)
		}
	}
	if domain == "" {
		return "", motmedelErrors.NewWithTrace(gmailErrors.ErrEmptyDomain)
	}

	messageIdRandomBuffer := make([]byte, 16)
	if _, err := rand.Read(messageIdRandomBuffer); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}
	builder.WriteString(
		fmt.Sprintf(
			"Message-ID: %s\r\n",
			fmt.Sprintf("<%d.%x@%s>", timeNow.UnixNano(), messageIdRandomBuffer, domain),
		),
	)

	body := message.Body

	builder.WriteString("MIME-Version: 1.0\r\n")
	if body != nil && message.Body.ContentType != "" {
		builder.WriteString(fmt.Sprintf("Content-Type: %s\r\n", message.Body.ContentType))
	}
	builder.WriteString("\r\n")
	if body != nil && len(body.Content) > 0 {
		builder.Write(body.Content)
	}

	return builder.String(), nil
}

func New(from, to, subject string, body *Body, options ...Option) (*Message, error) {
	if err := mailAddressValidation.Validate(from); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("mail address validate (from): %w", err))
	}

	if err := mailAddressValidation.Validate(to); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("mail address validate (to): %w", err))
	}

	if subject == "" {
		return nil, motmedelErrors.NewWithTrace(gmailErrors.ErrEmptySubject)
	}

	if body != nil && body.ContentType == "" {
		return nil, motmedelErrors.NewWithTrace(gmailErrors.ErrEmptyContentType)
	}

	config := &Message{
		From:    from,
		To:      to,
		Subject: subject,
		Body:    body,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config, nil
}

func WithFromName(fromName string) Option {
	return func(config *Message) {
		config.FromName = fromName
	}
}

func WithReplyTo(replyTo string) Option {
	return func(config *Message) {
		config.ReplyTo = replyTo
	}
}

func WithDomain(domain string) Option {
	return func(config *Message) {
		config.Domain = domain
	}
}
