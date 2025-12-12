package gmail

import (
	"encoding/base64"
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/mail/types/message"
	gmailUtilsErrors "github.com/altshiftab/gcp_utils/pkg/gmail/errors"
	"google.golang.org/api/gmail/v1"
)

func getMessagesService(gmailService *gmail.Service) (*gmail.UsersMessagesService, error) {
	if gmailService == nil {
		return nil, motmedelErrors.NewWithTrace(gmailUtilsErrors.ErrNilService)
	}

	gmailUsersService := gmailService.Users
	if gmailUsersService == nil {
		return nil, motmedelErrors.NewWithTrace(gmailUtilsErrors.ErrNilUsersService)
	}

	return gmailUsersService.Messages, nil
}

func SendMessage(msg *message.Message, service *gmail.Service) (*gmail.Message, error) {
	if service == nil {
		return nil, motmedelErrors.NewWithTrace(gmailUtilsErrors.ErrNilService)
	}

	if msg == nil {
		return nil, nil
	}

	msgString, err := msg.String()
	if err != nil {
		return nil, fmt.Errorf("message string: %w", err)
	}

	messagesService, err := getMessagesService(service)
	if err != nil {
		return nil, fmt.Errorf("get messages service: %w", err)
	}
	if messagesService == nil {
		return nil, motmedelErrors.NewWithTrace(gmailUtilsErrors.ErrNilUsersMessagesService)
	}

	sendCall := messagesService.Send("me", &gmail.Message{Raw: base64.URLEncoding.EncodeToString([]byte(msgString))})
	if sendCall == nil {
		return nil, motmedelErrors.NewWithTrace(gmailUtilsErrors.ErrNilUsersMessagesSendCall)
	}

	// "me" is a special UserID indicating the authenticated user
	sentMessage, err := sendCall.Do()
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("user messages send call: %w", err), msgString)
	}

	return sentMessage, nil
}
