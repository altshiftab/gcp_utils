package utils

import (
	"context"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/Motmedel/ecs_go/ecs"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"google.golang.org/api/gmail/v1"
)

func ParseGmailMessage(ctx context.Context, message *gmail.Message) (*ecs.Base, error) {
	if message == nil {
		return nil, nil
	}

	base := &ecs.Base{
		Event: &ecs.Event{
			Provider: "gmail",
			Kind:     "event",
			Category: []string{"email"},
			Type:     []string{"info"},
		},
	}

	var ecsEmail ecs.Email

	ecsEmail.OriginationTimestamp = time.UnixMilli(message.InternalDate).UTC().Format("2006-01-02T15:04:05.999Z")

	if messagePayload := message.Payload; messagePayload != nil {
		headers := make(map[string]string)
		for _, header := range message.Payload.Headers {
			headers[strings.ToLower(header.Name)] = header.Value
		}

		if val, ok := headers["subject"]; ok {
			ecsEmail.Subject = val
		}
		if val, ok := headers["message-id"]; ok {
			ecsEmail.MessageId = val
		}
		if val, ok := headers["content-type"]; ok {
			ecsEmail.ContentType = val
		}

		if val, ok := headers["from"]; ok {
			if addr, _ := ecs.ParseEmailAddress(val); addr != nil {
				ecsEmail.From = []*ecs.EmailAddress{addr}
			}
		}

		if val, ok := headers["to"]; ok {
			toAddressList, err := mail.ParseAddressList(val)
			if err != nil {
				slog.WarnContext(
					motmedelContext.WithErrorContextValue(
						ctx,
						motmedelErrors.NewWithTrace(fmt.Errorf("parse address list (to): %w", err), val),
					),
					"An error occurred when parsing the \"To\" header.",
				)
			}

			for _, address := range toAddressList {
				if addr, _ := ecs.ParseEmailAddress(address.Address); addr != nil {
					ecsEmail.To = append(ecsEmail.To, addr)
				}
			}
		}

		if val, ok := headers["reply-to"]; ok {
			replyToAddressList, err := mail.ParseAddressList(val)
			if err != nil {
				slog.WarnContext(
					motmedelContext.WithErrorContextValue(
						ctx,
						motmedelErrors.NewWithTrace(fmt.Errorf("parse address list (reply-to): %w", err), val),
					),
					"An error occurred when parsing the \"Reply-To\" header.",
				)
			}

			for _, address := range replyToAddressList {
				if addr, _ := ecs.ParseEmailAddress(address.Address); addr != nil {
					ecsEmail.ReplyTo = append(ecsEmail.ReplyTo, addr)
				}
			}
		}
	}

	for _, label := range message.LabelIds {
		if label == "SENT" {
			ecsEmail.Direction = "outbound"
		} else if label == "INBOX" {
			ecsEmail.Direction = "inbound"
		}
	}

	base.Email = &ecsEmail

	return base, nil
}
