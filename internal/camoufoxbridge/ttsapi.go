package camoufoxbridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"elevenflow/internal/subtitles"
)

// TTSRequest is input for one TTS chunk.
type TTSRequest struct {
	VoiceID         string
	ModelID         string
	LanguageCode    string
	Text            string
	Speed           float64
	Stability       float64
	SimilarityBoost float64
	Style           float64
	UseSpeakerBoost bool
	Sitekey         string
	ExportSRT       bool
}

const modelMultilingualV2 = "eleven_multilingual_v2"
const modelFlashV25 = "eleven_flash_v2_5"
const modelTurboV25 = "eleven_turbo_v2_5"
const modelElevenV3 = "eleven_v3"

func modelUsesFullVoiceSettings(modelID string) bool {
	switch strings.TrimSpace(strings.ToLower(modelID)) {
	case modelMultilingualV2, modelFlashV25, modelTurboV25:
		return true
	default:
		return false
	}
}

// ClampTTSSpeed limits speed for anonymous API (0.7–1.2). ≤0 → 1.0 default.
func ClampTTSSpeed(speed float64) float64 {
	if speed <= 0 {
		return 1
	}
	if speed < 0.7 {
		return 0.7
	}
	if speed > 1.2 {
		return 1.2
	}
	return speed
}

func snapStabilityV3(x float64) float64 {
	if x < 0.25 {
		return 0
	}
	if x < 0.75 {
		return 0.5
	}
	return 1
}

// buildVoiceSettings constructs the voice_settings payload for the API.
func buildVoiceSettings(req TTSRequest) map[string]any {
	speed := ClampTTSSpeed(req.Speed)
	if !modelUsesFullVoiceSettings(req.ModelID) {
		return map[string]any{"speed": speed}
	}
	return map[string]any{
		"speed":             speed,
		"stability":         req.Stability,
		"use_speaker_boost": req.UseSpeakerBoost,
		"similarity_boost":  req.SimilarityBoost,
		"style":             req.Style,
	}
}

// ttsStreamLine is one JSON line from the /with-timestamps/anonymous endpoint.
type ttsStreamLine struct {
	AudioBase64          string           `json:"audio_base64,omitempty"`
	NormalizedAlignment  *ttsAlignment    `json:"normalized_alignment,omitempty"`
	Alignment            *ttsAlignment    `json:"alignment,omitempty"`
}

type ttsAlignment struct {
	Characters                 []string  `json:"characters"`
	CharacterStartTimesSeconds []float64 `json:"character_start_times_seconds"`
	CharacterEndTimesSeconds   []float64 `json:"character_end_times_seconds"`
}

func (a *ttsAlignment) appendTo(chars *[]string, starts, ends *[]float64) {
	if a == nil {
		return
	}
	for i, c := range a.Characters {
		*chars = append(*chars, c)
		if i < len(a.CharacterStartTimesSeconds) {
			*starts = append(*starts, a.CharacterStartTimesSeconds[i])
		} else {
			*starts = append(*starts, 0)
		}
		if i < len(a.CharacterEndTimesSeconds) {
			*ends = append(*ends, a.CharacterEndTimesSeconds[i])
		} else if i < len(a.CharacterStartTimesSeconds) {
			*ends = append(*ends, a.CharacterStartTimesSeconds[i])
		} else {
			*ends = append(*ends, 0)
		}
	}
}

// callTTSAnonymous calls the ElevenLabs anonymous TTS API using the captcha token.
func callTTSAnonymous(ctx context.Context, req TTSRequest, captchaToken, proxyURL string) ([]byte, subtitles.Alignment, error) {
	// Build URL.
	var ttsURL string
	if req.ExportSRT {
		ttsURL = fmt.Sprintf("https://api.elevenlabs.io/v1/text-to-speech/%s/stream/with-timestamps/anonymous?output_format=mp3_44100_128", req.VoiceID)
	} else {
		ttsURL = fmt.Sprintf("https://api.elevenlabs.io/v1/text-to-speech/%s/stream/anonymous", req.VoiceID)
	}

	// Build request body.
	body := map[string]any{
		"hcaptcha_token": captchaToken,
		"language_code":  req.LanguageCode,
		"model_id":       req.ModelID,
		"text":           req.Text,
		"voice_settings": buildVoiceSettings(req),
	}
	// V3 settings block.
	if req.ModelID == modelElevenV3 {
		body["settings"] = map[string]float64{"stability": snapStabilityV3(req.Stability)}
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, subtitles.Alignment{}, fmt.Errorf("marshal body: %w", err)
	}

	// Build HTTP client with proxy.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	if proxyURL != "" {
		proxyParsed, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyParsed)
		}
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Minute}
	defer client.CloseIdleConnections()

	httpReq, err := http.NewRequestWithContext(ctx, "POST", ttsURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, subtitles.Alignment{}, err
	}

	// Headers mimicking Chrome from elevenlabs.io (matches webview2bridge behavior).
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "*/*")
	httpReq.Header.Set("Origin", "https://elevenlabs.io")
	httpReq.Header.Set("Referer", "https://elevenlabs.io/")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	httpReq.Header.Set("Sec-Fetch-Dest", "empty")
	httpReq.Header.Set("Sec-Fetch-Mode", "cors")
	httpReq.Header.Set("Sec-Fetch-Site", "same-site")
	httpReq.Header.Set("Sec-Ch-Ua", `"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"`)
	httpReq.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	httpReq.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")
	httpReq.Header.Set("Priority", "u=1, i")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, subtitles.Alignment{}, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, subtitles.Alignment{}, &ttsHTTPError{
			Status: resp.StatusCode,
			Body:   string(bodyBytes),
		}
	}

	if !req.ExportSRT {
		// Non-SRT: response is raw audio bytes.
		audio, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, subtitles.Alignment{}, fmt.Errorf("read audio: %w", err)
		}
		return audio, subtitles.Alignment{}, nil
	}

	// SRT mode: parse streaming JSON lines.
	var audioParts [][]byte
	var chars []string
	var starts, ends []float64

	decoder := json.NewDecoder(resp.Body)
	for decoder.More() {
		var line ttsStreamLine
		if err := decoder.Decode(&line); err != nil {
			// Try line-by-line parsing for NDJSON.
			break
		}
		if line.AudioBase64 != "" {
			raw, err := base64.StdEncoding.DecodeString(line.AudioBase64)
			if err == nil {
				audioParts = append(audioParts, raw)
			}
		}
		al := line.NormalizedAlignment
		if al == nil {
			al = line.Alignment
		}
		al.appendTo(&chars, &starts, &ends)
	}

	// If JSON decoder didn't work well, try line-by-line as fallback.
	if len(audioParts) == 0 {
		remaining, _ := io.ReadAll(resp.Body)
		allData := remaining
		for _, lineStr := range strings.Split(string(allData), "\n") {
			lineStr = strings.TrimSpace(lineStr)
			if lineStr == "" {
				continue
			}
			var line ttsStreamLine
			if err := json.Unmarshal([]byte(lineStr), &line); err != nil {
				continue
			}
			if line.AudioBase64 != "" {
				raw, err := base64.StdEncoding.DecodeString(line.AudioBase64)
				if err == nil {
					audioParts = append(audioParts, raw)
				}
			}
			al := line.NormalizedAlignment
			if al == nil {
				al = line.Alignment
			}
			al.appendTo(&chars, &starts, &ends)
		}
	}

	// Combine audio chunks.
	total := 0
	for _, p := range audioParts {
		total += len(p)
	}
	if total < 2 {
		return nil, subtitles.Alignment{}, fmt.Errorf("empty audio from timestamps stream")
	}

	audio := make([]byte, 0, total)
	for _, p := range audioParts {
		audio = append(audio, p...)
	}

	// Validate MP3 header.
	if len(audio) >= 3 {
		isID3 := audio[0] == 0x49 && audio[1] == 0x44 && audio[2] == 0x33
		isMP3Frame := audio[0] == 0xFF && (audio[1]&0xE0) == 0xE0
		if !isID3 && !isMP3Frame {
			return nil, subtitles.Alignment{}, fmt.Errorf("invalid mp3 after concat")
		}
	}

	align := subtitles.Alignment{
		Characters: chars,
		Starts:     starts,
		Ends:       ends,
	}

	if len(chars) == 0 {
		return nil, subtitles.Alignment{}, fmt.Errorf("missing alignment")
	}

	return audio, align, nil
}

// ttsHTTPError represents an HTTP error from the TTS API.
type ttsHTTPError struct {
	Status int
	Body   string
}

func (e *ttsHTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Status, truncate(e.Body, 300))
}

func (e *ttsHTTPError) IsUnusualActivity() bool {
	if e.Status == 401 {
		return true
	}
	low := strings.ToLower(e.Body)
	return strings.Contains(low, "detected_unusual_activity") ||
		strings.Contains(low, "unusual_activity") ||
		strings.Contains(low, "verify_authenticity")
}

func (e *ttsHTTPError) IsTransient() bool {
	return e.Status >= 500 || e.Status == 429
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
