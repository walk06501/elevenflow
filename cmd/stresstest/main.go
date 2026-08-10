// Stress test / benchmark cho chính server ElevenFlow đang chạy — bắn
// nhiều request /synthesize thật, đồng thời, để chủ động phát hiện điểm
// yếu (rate limit, chạm trần VPN, backpressure, hãng VPN nào tệ dưới tải
// thật) TRƯỚC khi khách hàng gặp phải, thay vì đợi bị phàn nàn rồi mới
// điều tra.
//
// QUAN TRỌNG — đây KHÔNG phải load test kiểu API thường: mỗi request là 1
// job TTS THẬT qua trình duyệt ảo thật + VPN thật + tài khoản ElevenLabs
// thật (giống hệt 1 khách hàng thật bấm tạo). KHÔNG có gì miễn phí ở đây —
// chạy total=100 nghĩa là tốn đúng 100 lượt tài nguyên thật. Mặc định cố
// tình ở mức vừa phải (total=40, concurrency=30 — hơi vượt MaxConcurrent
// mặc định 25 để xem thật backpressure hoạt động ra sao), không phải để
// chứng minh hệ thống chịu được cả nghìn request cùng lúc.
//
// Usage (chạy TRÊN hoặc CÙNG MẠNG với máy đang chạy elevenflow-server,
// secret đọc thẳng từ biến môi trường ELEVEN_SERVER_SECRET nếu có sẵn,
// giống hệt cách chính server đọc):
//
//	go run ./cmd/stresstest -voice-id <VOICE_ID> [-url http://localhost:8080] [-concurrency 30] [-total 40]
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// 3 kích cỡ văn bản thật để đồng thời exercise cả đường single-chunk lẫn
// multi-chunk-rồi-merge (ChunkMax mặc định 600 ký tự — xem config.go) —
// mỗi request thật ngẫu nhiên rơi vào 1 trong 3 cỡ, round-robin theo index
// để phân bố đều thay vì ngẫu nhiên (dễ tái lập lỗi hơn nếu cần chạy lại).
var textProfiles = []struct {
	name string
	text string
}{
	{"short", "Xin chào, đây là một đoạn văn bản ngắn để kiểm tra hệ thống."},
	{"medium", strings.Repeat("Đây là một câu kiểm tra hệ thống chuyển văn bản thành giọng nói. ", 12)},                                                                    // ~700 ký tự, vượt nhẹ ChunkMax 600 -> buộc phải chia 2 chunk
	{"long", strings.Repeat("Đây là một đoạn văn bản dài hơn để kiểm tra khả năng xử lý nhiều đoạn (chunk) liên tiếp và ghép lại thành 1 file âm thanh hoàn chỉnh. ", 25)}, // ~3000+ ký tự, nhiều chunk
}

type synthRequest struct {
	Text            string  `json:"text"`
	VoiceID         string  `json:"voice_id"`
	ModelID         string  `json:"model_id"`
	LanguageCode    string  `json:"language_code,omitempty"`
	Speed           float64 `json:"speed"`
	Stability       float64 `json:"stability"`
	SimilarityBoost float64 `json:"similarity_boost"`
	Style           float64 `json:"style"`
	UseSpeakerBoost bool    `json:"use_speaker_boost"`
	ExportSRT       bool    `json:"export_srt"`
	JobID           string  `json:"job_id"`
}

type result struct {
	idx      int
	profile  string
	status   int
	err      error
	dur      time.Duration
	bodySize int
	errBody  string
}

func main() {
	url := flag.String("url", "http://localhost:8080", "base URL của ElevenFlow server")
	secret := flag.String("secret", os.Getenv("ELEVEN_SERVER_SECRET"), "X-Api-Secret (mặc định đọc từ biến môi trường ELEVEN_SERVER_SECRET)")
	voiceID := flag.String("voice-id", "", "voice_id THẬT để test (bắt buộc)")
	modelID := flag.String("model-id", "eleven_flash_v2_5", "model_id")
	// Mặc định "vi" — xác nhận THẬT từ 1 lần chạy lỗi (2026-08-10):
	// eleven_flash_v2_5 (model mặc định của chính tool này) TỪ CHỐI
	// language_code rỗng với HTTP 400 "does not support language_code ''"
	// (không tự nhận diện như comment cũ ở đây từng đoán sai) — và lỗi này
	// chỉ lộ ra SAU KHI đã tốn 1 phiên VPN+trình duyệt thật, không phải lỗi
	// validate sớm, nên để trống mặc định làm lãng phí tài nguyên thật mỗi
	// lần chạy tool. "vi" khớp đối tượng khách hàng chính của hệ thống này.
	langCode := flag.String("lang", "vi", "language_code — BẮT BUỘC với các model enforce ngôn ngữ (flash/turbo/v3); rỗng sẽ 400 sau khi đã tốn 1 phiên thật")
	concurrency := flag.Int("concurrency", 30, "số request đồng thời (cố tình > MaxConcurrent mặc định 25 để test backpressure thật)")
	total := flag.Int("total", 40, "tổng số request sẽ bắn — MỖI request là 1 job thật, tốn tài nguyên thật, đừng đặt quá cao ở lần chạy đầu")
	timeout := flag.Duration("timeout", 6*time.Minute, "timeout tối đa cho MỖI request (job dài + nhiều lần rotate có thể mất vài phút)")
	flag.Parse()

	if *voiceID == "" {
		log.Fatal("cần -voice-id (voice_id thật, ví dụ 1 giọng đang dùng được trên hệ thống)")
	}
	if *secret == "" {
		log.Println("CẢNH BÁO: không có secret (ELEVEN_SERVER_SECRET trống và -secret không set) — chỉ hoạt động nếu server đang chạy không bật auth")
	}

	client := &http.Client{Timeout: *timeout}

	fmt.Printf("=== Stress test ElevenFlow: %s ===\n", *url)
	fmt.Printf("concurrency=%d total=%d timeout/request=%s voice_id=%s model_id=%s\n\n", *concurrency, *total, *timeout, *voiceID, *modelID)

	healthBefore := fetchHealth(client, *url, *secret)
	if healthBefore != nil {
		fmt.Println("--- /health TRƯỚC khi bắn ---")
		printHealth(healthBefore)
		fmt.Println()
	}

	jobs := make(chan int, *total)
	results := make(chan result, *total)
	var wg sync.WaitGroup

	start := time.Now()
	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				profile := textProfiles[idx%len(textProfiles)]
				r := fireOne(client, *url, *secret, *voiceID, *modelID, *langCode, idx, profile.name, profile.text)
				fmt.Printf("[%3d/%d] %-6s status=%-3d dur=%6.1fs %s\n",
					idx+1, *total, profile.name, r.status, r.dur.Seconds(), errSummary(r))
				results <- r
			}
		}()
	}
	for i := 0; i < *total; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(results)
	totalDur := time.Since(start)

	var all []result
	for r := range results {
		all = append(all, r)
	}

	healthAfter := fetchHealth(client, *url, *secret)

	printSummary(all, totalDur)

	if healthBefore != nil && healthAfter != nil {
		fmt.Println("\n--- /health SAU khi bắn xong ---")
		printHealth(healthAfter)
		fmt.Println("\n--- Delta per-hãng VPN (sau - trước) ---")
		printVPNDelta(healthBefore, healthAfter)
	}
}

func fireOne(client *http.Client, baseURL, secret, voiceID, modelID, lang string, idx int, profileName, text string) result {
	body := synthRequest{
		Text:            text,
		VoiceID:         voiceID,
		ModelID:         modelID,
		LanguageCode:    lang,
		Speed:           1.0,
		Stability:       0.5,
		SimilarityBoost: 0.75,
		UseSpeakerBoost: true,
		JobID:           fmt.Sprintf("stresstest-%d-%d", time.Now().Unix(), idx),
	}
	payload, _ := json.Marshal(body)

	t0 := time.Now()
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(baseURL, "/")+"/synthesize", bytes.NewReader(payload))
	if err != nil {
		return result{idx: idx, profile: profileName, err: err, dur: time.Since(t0)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Secret", secret)
	req.Header.Set("X-Request-Id", fmt.Sprintf("stresstest-%d", idx))

	resp, err := client.Do(req)
	dur := time.Since(t0)
	if err != nil {
		return result{idx: idx, profile: profileName, err: err, dur: dur}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	r := result{idx: idx, profile: profileName, status: resp.StatusCode, dur: dur, bodySize: len(b)}
	if resp.StatusCode != http.StatusOK {
		errText := string(b)
		if len(errText) > 300 {
			errText = errText[:300] + "..."
		}
		r.errBody = errText
	}
	return r
}

func errSummary(r result) string {
	if r.err != nil {
		return "LỖI CLIENT: " + r.err.Error()
	}
	if r.status != http.StatusOK {
		return "LỖI: " + r.errBody
	}
	return fmt.Sprintf("OK (%d bytes audio)", r.bodySize)
}

func printSummary(all []result, totalDur time.Duration) {
	var ok, fail int
	var durs []time.Duration
	statusCounts := map[int]int{}
	errCounts := map[string]int{}

	for _, r := range all {
		if r.err == nil && r.status == http.StatusOK {
			ok++
			durs = append(durs, r.dur)
		} else {
			fail++
			if r.err != nil {
				errCounts["client: "+r.err.Error()]++
			} else {
				errCounts[fmt.Sprintf("HTTP %d: %s", r.status, r.errBody)]++
			}
		}
		statusCounts[r.status]++
	}

	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })

	fmt.Printf("\n=== TỔNG KẾT ===\n")
	fmt.Printf("Tổng thời gian chạy: %s\n", totalDur)
	fmt.Printf("Thành công: %d/%d (%.1f%%)\n", ok, len(all), 100*float64(ok)/float64(len(all)))
	fmt.Printf("Thất bại:   %d/%d (%.1f%%)\n", fail, len(all), 100*float64(fail)/float64(len(all)))

	if len(durs) > 0 {
		sum := time.Duration(0)
		for _, d := range durs {
			sum += d
		}
		p := func(pct float64) time.Duration {
			i := int(float64(len(durs)-1) * pct)
			return durs[i]
		}
		fmt.Printf("\nĐộ trễ (chỉ tính request THÀNH CÔNG):\n")
		fmt.Printf("  min=%.1fs  avg=%.1fs  p50=%.1fs  p95=%.1fs  max=%.1fs\n",
			durs[0].Seconds(), (sum / time.Duration(len(durs))).Seconds(),
			p(0.50).Seconds(), p(0.95).Seconds(), durs[len(durs)-1].Seconds())
	}

	if len(statusCounts) > 0 {
		fmt.Printf("\nPhân loại theo HTTP status:\n")
		codes := make([]int, 0, len(statusCounts))
		for c := range statusCounts {
			codes = append(codes, c)
		}
		sort.Ints(codes)
		for _, c := range codes {
			fmt.Printf("  %d: %d lần\n", c, statusCounts[c])
		}
	}

	if len(errCounts) > 0 {
		fmt.Printf("\nPhân loại lỗi (đã gộp trùng):\n")
		type ec struct {
			msg string
			n   int
		}
		var list []ec
		for msg, n := range errCounts {
			list = append(list, ec{msg, n})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
		for _, e := range list {
			fmt.Printf("  x%-3d %s\n", e.n, e.msg)
		}
	}
}

func fetchHealth(client *http.Client, baseURL, secret string) map[string]any {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+"/health", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("X-Api-Secret", secret)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("không lấy được /health: %v", err)
		return nil
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		log.Printf("không parse được /health: %v", err)
		return nil
	}
	return out
}

func printHealth(h map[string]any) {
	for _, k := range []string{"status", "max_concurrent", "inflight", "persistent_pool_active_sessions", "queue_small_waiting", "queue_big_waiting"} {
		if v, ok := h[k]; ok {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}
	if vs, ok := h["vpn_provider_stats"].(map[string]any); ok {
		fmt.Println("  vpn_provider_stats:")
		names := make([]string, 0, len(vs))
		for n := range vs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			st, _ := vs[n].(map[string]any)
			fmt.Printf("    %-20s attempts=%v successes=%v rate=%v avg_ms=%v max_ms=%v\n",
				n, st["attempts"], st["successes"], st["success_rate"], st["avg_ms"], st["max_ms"])
		}
	}
}

func printVPNDelta(before, after map[string]any) {
	bvs, _ := before["vpn_provider_stats"].(map[string]any)
	avs, _ := after["vpn_provider_stats"].(map[string]any)
	if bvs == nil || avs == nil {
		fmt.Println("  (không có vpn_provider_stats để so sánh)")
		return
	}
	names := make([]string, 0, len(avs))
	for n := range avs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a, _ := avs[n].(map[string]any)
		b, _ := bvs[n].(map[string]any)
		aAttempts := asFloat(a["attempts"])
		bAttempts := asFloat(b["attempts"])
		aSucc := asFloat(a["successes"])
		bSucc := asFloat(b["successes"])
		deltaAttempts := aAttempts - bAttempts
		deltaSucc := aSucc - bSucc
		rate := 1.0
		if deltaAttempts > 0 {
			rate = deltaSucc / deltaAttempts
		}
		fmt.Printf("  %-20s +%d attempts, +%d successes trong lúc test (tỉ lệ riêng đợt này: %.0f%%)\n",
			n, int(deltaAttempts), int(deltaSucc), rate*100)
	}
}

func asFloat(v any) float64 {
	f, _ := v.(float64)
	return f
}
