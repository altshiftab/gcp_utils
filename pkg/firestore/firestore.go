package firestore

import (
	gcpFirestore "cloud.google.com/go/firestore"
	gcpFirestoreRest "cloud.google.com/go/firestore/apiv1"
	"context"
	"fmt"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"log/slog"
	"os"
)

type ClientContextKeyType struct{}
type RestClientContextKeyType struct{}

var (
	ClientContextKey     ClientContextKeyType     = struct{}{}
	RestClientContextKey RestClientContextKeyType = struct{}{}
)

func MakeClientContextPair(client *gcpFirestore.Client) [2]any {
	return [2]any{ClientContextKey, client}
}

func MakeRestClientContextPair(restClient *gcpFirestoreRest.Client) [2]any {
	return [2]any{RestClientContextKey, restClient}
}

func ClientFromCtx(ctx context.Context) *gcpFirestore.Client {
	client, _ := ctx.Value(ClientContextKey).(*gcpFirestore.Client)
	return client
}

func RestClientFromCtx(ctx context.Context) *gcpFirestoreRest.Client {
	restClient, _ := ctx.Value(RestClientContextKey).(*gcpFirestoreRest.Client)
	return restClient
}

func MakeClientFatal(ctx context.Context, projectId string) *gcpFirestore.Client {
	client, err := gcpFirestore.NewClient(ctx, projectId)
	if err != nil {
		slog.ErrorContext(
			motmedelContext.WithErrorContextValue(
				ctx,
				motmedelErrors.NewWithTrace(fmt.Errorf("firestore new client: %w", err), projectId),
			),
			"An error occurred when creating a Firestore client.",
		)
		os.Exit(1)
	}
	return client
}

func MakeRestClientFatal(ctx context.Context) *gcpFirestoreRest.Client {
	restClient, err := gcpFirestoreRest.NewRESTClient(ctx)
	if err != nil {
		slog.ErrorContext(
			motmedelContext.WithErrorContextValue(
				ctx,
				motmedelErrors.NewWithTrace(fmt.Errorf("firestore new rest client: %w", err)),
			),
			"An error occurred when creating a Firestore REST client.",
		)
		os.Exit(1)
	}

	return restClient
}
