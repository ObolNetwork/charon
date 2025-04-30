// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sseclient

import (
	"bufio"
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
)

func TestParseEventRetry(t *testing.T) {
	r := bufio.NewReader(bytes.NewBufferString("retry: 10\n\n"))
	client := &Client{}

	_, err := client.parseEvent(r)
	require.NoError(t, err)
	require.Equal(t, 10*time.Millisecond, client.Retry)
}

func TestParseEventInvalidRetry(t *testing.T) {
	r := bufio.NewReader(bytes.NewBufferString("retry: ???\n\n"))
	client := &Client{}

	_, err := client.parseEvent(r)
	require.NoError(t, err)
	require.Equal(t, time.Duration(0), client.Retry)
}

func TestParseEvent(t *testing.T) {
	tests := []struct {
		name  string
		data  string
		event *Event
		err   error
	}{
		{
			name: "parse no data",
			data: "\n\n",
			event: &Event{
				ID:    "",
				Event: "message",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse id",
			data: "id: 123\n\n",
			event: &Event{
				ID:    "123",
				Event: "message",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse event",
			data: "event: create\n\n",
			event: &Event{
				ID:    "",
				Event: "create",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse data",
			data: "data: some data\n\n",
			event: &Event{
				ID:    "",
				Event: "message",
				Data:  []byte("some data"),
			},
			err: nil,
		},
		{
			name: "parse multiline data",
			data: "data: some data\ndata: multiline data\n\n",
			event: &Event{
				ID:    "",
				Event: "message",
				Data:  []byte("some data\nmultiline data"),
			},
			err: nil,
		},
		{
			name: "parse multiline data complex",
			data: "data: some data\r\ndata: multiline data\r\n\r\n",
			event: &Event{
				ID:    "",
				Event: "message",
				Data:  []byte("some data\nmultiline data"),
			},
			err: nil,
		},
		{
			name: "parse empty type",
			data: ": some comment\n\n",
			event: &Event{
				ID:    "",
				Event: "message",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse unsupported field",
			data: "unsupported field\n\n",
			event: &Event{
				ID:    "",
				Event: "message",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse multiple types",
			data: "id:123\nevent:create\ndata:this is some data\n\n",
			event: &Event{
				ID:    "123",
				Event: "create",
				Data:  []byte("this is some data"),
			},
			err: nil,
		},
		{
			name: "parse multiple types space",
			data: "id: 123\nevent: create\ndata: this is some data\n\n",
			event: &Event{
				ID:    "123",
				Event: "create",
				Data:  []byte("this is some data"),
			},
			err: nil,
		},
		{
			name: "parse multiple types new line",
			data: `id: 123
event: create
data: this is some data
unsupported field
: some comment
data: multiline data

`,
			event: &Event{
				ID:    "123",
				Event: "create",
				Data:  []byte("this is some data\nmultiline data"),
			},
			err: nil,
		},
		{
			name:  "incomplete event",
			data:  "data: test", // missing \n to be complete event
			event: nil,
			err:   errors.New("incomplete event at the end of the stream"),
		},
		{
			name:  "empty data EOF",
			data:  "",
			event: nil,
			err:   io.EOF,
		},
		{
			name:  "EOF",
			data:  "data: test\n",
			event: nil,
			err:   io.EOF,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := bufio.NewReader(bytes.NewBufferString(test.data))
			client := &Client{}

			event, err := client.parseEvent(r)
			if test.event != nil {
				require.Equal(t, test.event.Event, event.Event)
				require.Equal(t, test.event.Data, event.Data)
				require.Equal(t, test.event.ID, event.ID)
			}
			if test.err != nil {
				require.ErrorContains(t, err, test.err.Error())
			}
		})
	}
}
