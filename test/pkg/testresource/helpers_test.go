package testresource

import (
	"context"
	"io"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

type eventHistoryStub struct {
	client.APIClient
	count int
	since string
}

var _ client.APIClient = (*eventHistoryStub)(nil)

func (api *eventHistoryStub) Events(ctx context.Context, opts client.EventsListOptions) client.EventsResult {
	api.since = opts.Since
	messages := make(chan events.Message)
	errors := make(chan error, 1)
	go func() {
		for index := 0; index < api.count; index++ {
			select {
			case messages <- events.Message{Type: events.ImageEventType, Actor: events.Actor{ID: "replayed-image"}}:
			case <-ctx.Done():
				errors <- ctx.Err()
				return
			}
		}
		errors <- io.EOF
	}()
	return client.EventsResult{Messages: messages, Err: errors}
}
