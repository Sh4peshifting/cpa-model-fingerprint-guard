package fingerprint

import (
	"encoding/json"
	"strings"

	"github.com/bul1horn/cpa-model-fingerprint-guard/internal/guard"
)

// decodeSample adapts the host's normalized JSON response. The SDK performs the
// numeric parsing, strict validation, feature extraction and ranking.
func decodeSample(protocol string, body []byte) (string, guard.Status) {
	type part struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	var data struct {
		Type       string          `json:"type"`
		Error      json.RawMessage `json:"error"`
		Status     string          `json:"status"`
		StopReason string          `json:"stop_reason"`
		Content    []part          `json:"content"`
		Output     []struct {
			Type    string `json:"type"`
			Content []part `json:"content"`
		} `json:"output"`
		Choices []struct {
			Finish  string `json:"finish_reason"`
			Message struct {
				Content string `json:"content"`
				Refusal string `json:"refusal"`
			} `json:"message"`
		} `json:"choices"`
	}
	if len(body) > 2<<20 || json.Unmarshal(body, &data) != nil {
		return "", guard.Inconclusive
	}
	if data.Type == "error" || len(data.Error) > 0 && string(data.Error) != "null" {
		return "", guard.Transient
	}
	var text strings.Builder
	switch protocol {
	case "openai-response":
		if data.Status != "completed" {
			return "", guard.Inconclusive
		}
		for _, item := range data.Output {
			if item.Type != "message" {
				continue
			}
			for _, p := range item.Content {
				if p.Type == "output_text" {
					text.WriteString(p.Text)
				}
			}
		}
	case "claude":
		if data.StopReason != "end_turn" && data.StopReason != "stop" && data.StopReason != "completed" {
			return "", guard.Inconclusive
		}
		for _, p := range data.Content {
			if p.Type == "text" {
				text.WriteString(p.Text)
			}
		}
	case "openai":
		if len(data.Choices) == 0 {
			return "", guard.Inconclusive
		}
		c := data.Choices[0]
		if c.Message.Refusal != "" || c.Finish != "stop" && c.Finish != "completed" && c.Finish != "end_turn" {
			return "", guard.Inconclusive
		}
		text.WriteString(c.Message.Content)
	}
	if text.Len() == 0 {
		return "", guard.Inconclusive
	}
	return text.String(), ""
}
