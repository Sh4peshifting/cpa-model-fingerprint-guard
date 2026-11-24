package cpa

import "testing"

func TestSSEErrorFraming(t *testing.T) {
	var buf eventBuffer
	var events []string
	emit := func(_ int, code, _ string) { events = append(events, code) }
	buf.feed([]byte("event: er"), emit)
	buf.feed([]byte("ror\r\ndata: {\"error\":{\"type\":"), emit)
	buf.feed([]byte("\"server_is_overloaded\"}}\r\n\r\n"), emit)
	buf.feed([]byte("data: {\"type\":\"message.delta\",\"content\":\"server_is_overloaded\"}\n\n"), emit)
	buf.feed([]byte("data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"different\"}}}\n\n"), emit)
	buf.feed([]byte("event: error"), emit)
	buf.feed([]byte(`data: {"code":"separate_frame"}`), emit)
	if len(events) != 3 || events[0] != "server_is_overloaded" || events[1] != "different" || events[2] != "separate_frame" {
		t.Fatalf("events = %v", events)
	}
}
