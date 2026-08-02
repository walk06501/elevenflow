package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"elevenflow/internal/appconfig"
	"elevenflow/internal/authlocal"
	"elevenflow/internal/buildinfo"
	"elevenflow/internal/deviceid"
	"elevenflow/internal/diaglog"
	"elevenflow/internal/outputdir"
	"elevenflow/internal/outputname"
	"elevenflow/internal/proxyserver"
	"elevenflow/internal/savedvoices"
	"elevenflow/internal/subtitles"
	"elevenflow/internal/tts"
	"elevenflow/internal/webview2bridge"
)

// App is the Wails application struct. All exported methods become JS bindings.
type App struct {
	ctx               context.Context
	proxyClient       *proxyserver.Client
	commercialAuth    bool
	deviceFingerprint string
	startupDone       uint32 // atomic: 1 sau khi startup() hoàn tất (frontend chờ trước khi đọc auth)
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.proxyClient = proxyserver.Default()

	df, err := deviceid.StableFingerprint()
	if err != nil {
		df = ""
	}
	if df == "" {
		df = "unknown-device"
	}
	a.deviceFingerprint = df
	a.proxyClient.SetDeviceFingerprint(df)

	var pub proxyserver.PublicConfig
	var cfgErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		cfgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		pub, cfgErr = proxyserver.FetchPublicConfig(cfgCtx, a.proxyClient.ServerURL())
		cancel()
		if cfgErr == nil {
			break
		}
	}
	if cfgErr == nil {
		a.commercialAuth = pub.CommercialAuth
	}
	// Xóa session.blob cũ (JWT) nếu còn — không còn khôi phục phiên từ đĩa.
	_ = authlocal.New(df).Clear()

	// Không LoadInto JWT từ đĩa — mỗi lần mở app phải đăng nhập lại (chỉ tùy chọn ghi nhớ form).

	a.emit(ProgressPayload{
		Phase:    "rotate",
		JobID:    -1,
		WorkerID: -1,
		Message:  "Đã sẵn sàng.",
	})
	baseURL := a.proxyClient.ServerURL()
	if cfgErr != nil {
		msg := "Không tải được cấu hình từ máy chủ. Kiểm tra Internet và thử lại."
		if buildinfo.Mode == "development" {
			msg = fmt.Sprintf("[dev] /api/config: %v · %s", cfgErr, baseURL)
		}
		a.emit(ProgressPayload{
			Phase:    "rotate",
			JobID:    -1,
			WorkerID: -1,
			Message:  msg,
		})
	} else if a.commercialAuth {
		msg := "Đã kết nối máy chủ."
		if buildinfo.Mode == "development" {
			msg = fmt.Sprintf("[dev] commercial auth · %s", baseURL)
		}
		a.emit(ProgressPayload{
			Phase:    "rotate",
			JobID:    -1,
			WorkerID: -1,
			Message:  msg,
		})
	}
	atomic.StoreUint32(&a.startupDone, 1)
}

// IsStartupComplete — true sau khi startup() đã chạy xong (đọc /api/config).
// Frontend chờ cờ này để tránh race với GetCommercialAuthRequired.
func (a *App) IsStartupComplete() bool {
	return atomic.LoadUint32(&a.startupDone) != 0
}

// --- Build info ---

type BuildInfo struct {
	Mode    string `json:"mode"`
	Version string `json:"version"`
}

// SavedLoginPrefs — email/mật khẩu đã ghi nhớ (chỉ điền form), không phải JWT.
type SavedLoginPrefs struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Saved    bool   `json:"saved"`
}

// CommercialQuotaDTO — hạn ký tự từ máy chủ (hiển thị trên UI).
type CommercialQuotaDTO struct {
	Unlimited bool  `json:"unlimited"`
	CharsUsed int64 `json:"charsUsed"`
	MaxChars  int64 `json:"maxChars"`
	Remaining int64 `json:"remaining"`
}

func (a *App) GetBuildInfo() BuildInfo {
	return BuildInfo{Mode: buildinfo.Mode, Version: buildinfo.AppVersion}
}

// --- Server health ---

func (a *App) CheckServer() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return a.proxyClient.HealthCheck(ctx)
}

// --- Output directory helpers ---

func (a *App) SelectOutputDir() (string, error) {
	dir, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Chọn thư mục lưu file MP3",
	})
	if err != nil {
		return "", err
	}
	return dir, nil
}

// ImportTextFile mở hộp thoại chọn file văn bản, đọc UTF-8 (chuẩn hóa xuống dòng \n), trả nội dung.
// Người dùng bấm Hủy → chuỗi rỗng, không lỗi.
func (a *App) ImportTextFile() (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("ứng dụng chưa sẵn sàng")
	}
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Chọn file để nhập nội dung",
		Filters: []runtime.FileFilter{
			{DisplayName: "Văn bản (*.txt, *.md, *.srt)", Pattern: "*.txt;*.md;*.srt"},
			{DisplayName: "Tất cả file (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("đọc file: %w", err)
	}
	s := string(data)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ToValidUTF8(s, "\uFFFD")
	return s, nil
}

// SavedVoice — Voice ID tùy chỉnh lưu trong %UserConfigDir%/ElevenFlow/saved_voices.json.
type SavedVoice struct {
	VoiceID string `json:"voiceId"`
	Label   string `json:"label"`
}

// ListSavedVoices trả danh sách giọng đã lưu (sắp xếp theo nhãn).
func (a *App) ListSavedVoices() ([]SavedVoice, error) {
	list, err := savedvoices.Load()
	if err != nil {
		return nil, err
	}
	out := make([]SavedVoice, len(list))
	for i := range list {
		out[i] = SavedVoice{VoiceID: list[i].VoiceID, Label: list[i].Label}
	}
	return out, nil
}

// AddSavedVoice thêm hoặc cập nhật nhãn khi trùng Voice ID.
func (a *App) AddSavedVoice(voiceID, label string) error {
	return savedvoices.Add(voiceID, label)
}

// RemoveSavedVoice xóa một Voice ID khỏi file lưu.
func (a *App) RemoveSavedVoice(voiceID string) error {
	return savedvoices.Remove(voiceID)
}

// DefaultOutputDir là thư mục gốc xuất mặc định: thư mục "output" cạnh file .exe
// (khi chạy go run dùng ./output trong cwd để tránh ghi vào Temp).
func (a *App) DefaultOutputDir() string {
	return outputdir.BesideExecutable()
}

// PromptOpenOutputFolder hiện hộp thoại hỏi có mở thư mục trong Explorer hay không.
func (a *App) PromptOpenOutputFolder(folder string) (bool, error) {
	folder = filepath.Clean(strings.TrimSpace(folder))
	if folder == "" || a.ctx == nil {
		return false, nil
	}
	const btnOpen = "Mở thư mục"
	const btnClose = "Đóng"
	sel, err := runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
		Type:          runtime.QuestionDialog,
		Title:         "ElevenFlow — hoàn thành",
		Message:       "Tạo audio xong.\n\nMở thư mục đầu ra trong File Explorer?\n\n" + folder,
		Buttons:       []string{btnOpen, btnClose},
		DefaultButton: btnOpen,
		CancelButton:  btnClose,
	})
	if err != nil {
		return false, err
	}
	s := strings.TrimSpace(sel)
	// Windows: QuestionDialog → MessageBox MB_YESNO, Wails trả về "Yes"/"No" (không dùng nhãn Buttons).
	if strings.EqualFold(s, "Yes") || strings.EqualFold(s, "OK") {
		return true, nil
	}
	if strings.EqualFold(s, "No") || strings.EqualFold(s, "Cancel") {
		return false, nil
	}
	return strings.EqualFold(s, btnOpen), nil
}

func (a *App) OpenFolder(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	path = filepath.Clean(path)
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	_ = exec.Command("explorer", path).Start()
}

// --- Batch TTS ---

// GenerateParams là input từ UI cho 1 batch TTS. Text sẽ được chia thành các
// chunk ≤600 ký tự (ưu tiên biên câu) và phân phối qua MaxWorkers WebView2
// instance song song.
type GenerateParams struct {
	VoiceID          string  `json:"voiceId"`
	ModelID          string  `json:"modelId"`
	LanguageCode     string  `json:"languageCode"`
	Speed            float64 `json:"speed"`
	Stability        float64 `json:"stability"`       // 0–1, multilingual v2
	SimilarityBoost  float64 `json:"similarityBoost"` // 0–1
	Style            float64 `json:"style"`           // 0–1 style exaggeration
	UseSpeakerBoost  bool    `json:"useSpeakerBoost"`
	Text             string  `json:"text"`
	OutputDir        string  `json:"outputDir"`
	OutputFilePrefix string  `json:"outputFilePrefix"` // tên gốc (không .mp3) cho từng dòng + file ghép
	MaxWorkers       int     `json:"maxWorkers"`
	ExportSRT        bool    `json:"exportSrt"`     // mode 1 khối text: xuất .srt ghép khớp output.mp3
	ParagraphMode    bool    `json:"paragraphMode"` // mode đa đoạn: mỗi đoạn → 1 file đánh số (không SRT)
	// Speakers — bảng người nói cho mode hội thoại (marker #Key → VoiceID).
	Speakers []DialogueSpeaker `json:"speakers"`
}

// DialogueSpeaker — cấu hình 1 người nói trong hội thoại (đồng bộ appconfig.Speaker).
type DialogueSpeaker struct {
	Key     int    `json:"key"`
	VoiceID string `json:"voiceId"`
	Note    string `json:"note"`
}

type ProgressPayload struct {
	Done     int    `json:"done"`
	Total    int    `json:"total"`
	Phase    string `json:"phase"` // "rotate" | "tts" | "done" | "error"
	JobID    int    `json:"jobId"`
	WorkerID int    `json:"workerId"` // -1 = không gắn worker (merge / startup)
	Message  string `json:"message"`
}

// LanguageOption — language_code gửi API + nhãn hiển thị (ElevenLabs Help Center).
type LanguageOption struct {
	Code  string `json:"code"`
	Label string `json:"label"`
}

// SupportedLanguagesForModel trả về mapping đầy đủ theo model (chỉ các mã API hỗ trợ).
func (a *App) SupportedLanguagesForModel(modelID string) []LanguageOption {
	raw := webview2bridge.SupportedLanguagesForModel(modelID)
	out := make([]LanguageOption, len(raw))
	for i := range raw {
		out[i] = LanguageOption{Code: raw[i].Code, Label: raw[i].Label}
	}
	return out
}

func (a *App) emit(p ProgressPayload) {
	diaglog.Append("tts:progress", p)
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "tts:progress", p)
}

// GenerateBatch: chia text (ChunkTextForTTS, trần 600 rune/đoạn) → webview2bridge.Pool.
// Số worker: MinTTSWorkers..MaxTTSWorkers (2..3); autoscale theo pool khi AutoScaleWorkersToProxyPool
// và không SharedProxyLease; lease chung khi SharedProxyLease.
func (a *App) GenerateBatch(params GenerateParams) ([]tts.JobResult, error) {
	if a.commercialAuth {
		if err := a.proxyClient.EnsureFreshToken(context.Background()); err != nil {
			return nil, fmt.Errorf("phiên đăng nhập: %w", err)
		}
		if _, _, _, _, ok := a.proxyClient.SessionSnapshot(); !ok {
			return nil, fmt.Errorf("vui lòng đăng nhập (tài khoản bắt buộc trên máy chủ)")
		}
	}

	pieces := webview2bridge.ChunkTextForTTS(params.Text, 600)
	var quotaNeed int64
	for _, p := range pieces {
		quotaNeed += int64(utf8.RuneCountInString(p))
	}
	if a.commercialAuth && quotaNeed > 0 {
		if err := a.proxyClient.CommercialQuotaCheck(context.Background(), quotaNeed); err != nil {
			return nil, err
		}
	}

	if params.VoiceID == "" || params.ModelID == "" {
		return nil, fmt.Errorf("voice ID và model ID không được để trống")
	}
	params.MaxWorkers = a.resolveMaxWorkers()
	params.Speed = webview2bridge.ClampTTSSpeed(params.Speed)
	params.Stability = clamp01(params.Stability)
	params.SimilarityBoost = clamp01(params.SimilarityBoost)
	params.Style = clamp01(params.Style)
	if params.LanguageCode == "" {
		params.LanguageCode = "en"
	}
	if params.OutputDir == "" {
		params.OutputDir = outputdir.BesideExecutable()
	}
	if err := os.MkdirAll(params.OutputDir, 0o700); err != nil {
		return nil, err
	}

	batchDir, err := outputname.NextBatchSubdir(params.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("tạo thư mục lô xuất: %w", err)
	}
	diaglog.Append("generate_batch_start", map[string]any{
		"version":       buildinfo.AppVersion,
		"mode":          buildinfo.Mode,
		"chunkCount":    len(pieces),
		"batchDir":      batchDir,
		"workers":       params.MaxWorkers,
		"sharedLease":   buildinfo.SharedProxyLease,
		"voiceIdPrefix": prefixID(params.VoiceID),
		"modelId":       params.ModelID,
	})
	fileStem := outputname.SanitizeStem(params.OutputFilePrefix)

	cfg := webview2bridge.Config{
		NumWorkers:       params.MaxWorkers,
		SharedProxyLease: buildinfo.SharedProxyLease,
		MaxChars:         600,
		OutputDir:        batchDir,
		OutputFileStem:   fileStem,
		Voice:            params.VoiceID,
		Model:            params.ModelID,
		LanguageCode:     params.LanguageCode,
		Speed:            params.Speed,
		Stability:        params.Stability,
		SimilarityBoost:  params.SimilarityBoost,
		Style:            params.Style,
		UseSpeakerBoost:  params.UseSpeakerBoost,
		ExportSRT:        params.ExportSRT,
		Provider:         a.newProvider(),
		Emit:             a.poolEmit(),
	}
	chunkResults, err := webview2bridge.Run(context.Background(), params.Text, cfg)
	if err != nil {
		diaglog.Append("generate_batch_run_error", map[string]any{"error": err.Error()})
		return nil, err
	}
	out := make([]tts.JobResult, 0, len(chunkResults))
	allOK := len(chunkResults) > 0
	for _, r := range chunkResults {
		out = append(out, tts.JobResult{
			ID:      r.ID,
			OK:      r.OK,
			Message: r.Message,
			Output:  r.Output,
		})
		if !r.OK {
			allOK = false
		}
	}

	// Ghép tự động khi đủ chunk OK. File nằm trong thư mục lô (batchDir).
	// Nếu có chunk fail → bỏ qua merge để user retry/can thiệp tay (nhân
	// bản chunk lỗi thì file ghép sẽ thiếu/lệch nội dung).
	if allOK {
		mergeStem := fileStem
		if mergeStem == "" {
			mergeStem = "output"
		}
		mergeFile := mergeStem + ".mp3"
		mergedPath := filepath.Join(batchDir, mergeFile)
		mergeMsg := fmt.Sprintf("Đang ghép %d dòng vào %s…", len(chunkResults), mergeFile)
		if p := webview2bridge.FindBundledFFmpeg(); p != "" {
			mergeMsg = fmt.Sprintf("Đang ghép %d dòng (ffmpeg + khoảng lặng 0.5s) → %s…", len(chunkResults), mergeFile)
		}
		a.emit(ProgressPayload{
			Phase:    "merge",
			JobID:    -1,
			WorkerID: -1,
			Message:  mergeMsg,
			Done:     len(chunkResults),
			Total:    len(chunkResults),
		})
		bytes, mergeErr := webview2bridge.MergeChunks(chunkResults, mergedPath)
		if mergeErr != nil {
			a.emit(ProgressPayload{
				Phase:    "error",
				JobID:    -1,
				WorkerID: -1,
				Message:  "Ghép file lỗi: " + mergeErr.Error(),
				Done:     len(chunkResults),
				Total:    len(chunkResults),
			})
		} else {
			a.emit(ProgressPayload{
				Phase:    "merge",
				JobID:    -1,
				WorkerID: -1,
				Message: fmt.Sprintf("Đã ghép %d dòng → %s (%.2f MB)",
					len(chunkResults), mergeFile, float64(bytes)/(1024*1024)),
				Done:  len(chunkResults),
				Total: len(chunkResults),
			})
			if n := removePerLineChunksAfterMerge(chunkResults, mergedPath); n > 0 {
				a.emit(ProgressPayload{
					Phase:    "merge",
					JobID:    -1,
					WorkerID: -1,
					Message:  fmt.Sprintf("Đã xóa %d file dòng tạm; chỉ còn %s.", n, mergeFile),
					Done:     len(chunkResults),
					Total:    len(chunkResults),
				})
			}
			out = append(out, tts.JobResult{
				ID:      -1,
				OK:      true,
				Message: fmt.Sprintf("%s (%d bytes)", mergeFile, bytes),
				Output:  mergedPath,
			})

			if params.ExportSRT {
				srtPath := filepath.Join(batchDir, mergeStem+".srt")
				if err := writeMergedSRT(chunkResults, srtPath); err != nil {
					a.emit(ProgressPayload{
						Phase: "error", JobID: -2, WorkerID: -1,
						Message: "Tạo SRT lỗi: " + err.Error(),
						Done:    len(chunkResults), Total: len(chunkResults),
					})
				} else {
					a.emit(ProgressPayload{
						Phase: "merge", JobID: -2, WorkerID: -1,
						Message: "Đã tạo phụ đề: " + filepath.Base(srtPath),
						Done:    len(chunkResults), Total: len(chunkResults),
					})
					out = append(out, tts.JobResult{
						ID:      -2,
						OK:      true,
						Message: filepath.Base(srtPath),
						Output:  srtPath,
					})
				}
			}
		}
	}

	if a.commercialAuth {
		var quotaConsumed int64
		for _, r := range chunkResults {
			if r.ID >= 0 && r.ID < len(pieces) && r.OK {
				quotaConsumed += int64(utf8.RuneCountInString(pieces[r.ID]))
			}
		}
		if quotaConsumed > 0 {
			if err := a.proxyClient.CommercialConsumeChars(context.Background(), quotaConsumed); err != nil {
				a.emit(ProgressPayload{
					Phase:    "error",
					JobID:    -1,
					WorkerID: -1,
					Message:  "Cảnh báo đồng bộ hạn mức ký tự: " + err.Error(),
					Done:     len(chunkResults),
					Total:    len(chunkResults),
				})
			}
		}
	}

	okN, failN := 0, 0
	for _, r := range chunkResults {
		if r.OK {
			okN++
		} else {
			failN++
		}
	}
	diaglog.Append("generate_batch_done", map[string]any{
		"chunks_ok": okN, "chunks_fail": failN, "merged_extra": len(out) > len(chunkResults),
	})

	return out, nil
}

// resolveMaxWorkers chọn số luồng cuối: cap MinTTSWorkers..MaxTTSWorkers,
// autoscale theo proxy pool khi bật AutoScaleWorkersToProxyPool và không SharedProxyLease.
func (a *App) resolveMaxWorkers() int {
	maxW := buildinfo.MaxTTSWorkers
	if buildinfo.AutoScaleWorkersToProxyPool && !buildinfo.SharedProxyLease {
		capCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		poolC, maxL, errCap := a.proxyClient.ProxyPoolCapacity(capCtx)
		cancel()
		if errCap != nil {
			diaglog.Append("workers_autoscale_skip", map[string]any{"error": errCap.Error(), "fallback": maxW})
		} else if poolC <= 0 {
			diaglog.Append("workers_autoscale_pool_zero", map[string]any{"fallback": maxW})
		} else {
			ceiling := min(buildinfo.MaxTTSWorkers, min(poolC, maxL))
			scaled := max(buildinfo.MinTTSWorkers, ceiling)
			diaglog.Append("workers_autoscale", map[string]any{
				"poolCount": poolC, "maxLeases": maxL, "ceiling": ceiling, "scaled": scaled, "cap": buildinfo.MaxTTSWorkers,
			})
			maxW = scaled
		}
	}
	return max(buildinfo.MinTTSWorkers, min(maxW, buildinfo.MaxTTSWorkers))
}

// newProvider tạo ProxyProvider phù hợp chế độ lease.
func (a *App) newProvider() webview2bridge.ProxyProvider {
	if buildinfo.SharedProxyLease {
		return webview2bridge.NewPoolProviderShared(a.proxyClient)
	}
	return webview2bridge.NewPoolProvider(a.proxyClient)
}

// poolEmit cầu nối progress của pool → EventsEmit UI.
func (a *App) poolEmit() webview2bridge.EmitFn {
	return func(workerID int, chunkID int, phase, message string, done, total int) {
		a.emit(ProgressPayload{
			Done: done, Total: total, Phase: phase,
			JobID: chunkID, WorkerID: workerID, Message: message,
		})
	}
}

// writeMergedSRT dựng .srt ghép từ alignment các chunk (đã sort theo ID global),
// offset thời gian khớp với cách MergeChunks ghép (gap 0.5s khi có ffmpeg).
func writeMergedSRT(results []webview2bridge.ChunkResult, srtPath string) error {
	gap := 0.0
	if webview2bridge.FindBundledFFmpeg() != "" {
		gap = 0.5
	}
	sorted := make([]webview2bridge.ChunkResult, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	parts := make([]subtitles.Alignment, 0, len(sorted))
	for _, r := range sorted {
		parts = append(parts, r.Alignment)
	}
	merged := subtitles.MergeAlignments(parts, gap)
	if merged.Len() == 0 {
		return fmt.Errorf("không có dữ liệu alignment (model có thể không trả timestamps)")
	}
	srt, err := subtitles.BuildSRT(merged, subtitles.DefaultBuildOptions())
	if err != nil {
		return err
	}
	return os.WriteFile(srtPath, []byte(srt), 0o644)
}

// GenerateParagraphs: tách Text thành nhiều đoạn, mỗi đoạn → 1 file audio đánh
// số tăng dần (001.mp3, 002.mp3… hoặc <prefix>_001.mp3). Tất cả chunk của mọi
// đoạn đẩy chung vào 1 pool để tối đa hóa số luồng (đoạn ít chunk không để luồng
// rảnh); sau khi xong gom chunk theo đoạn rồi ghép. Không xuất SRT ở mode này.
func (a *App) GenerateParagraphs(params GenerateParams) ([]tts.JobResult, error) {
	if a.commercialAuth {
		if err := a.proxyClient.EnsureFreshToken(context.Background()); err != nil {
			return nil, fmt.Errorf("phiên đăng nhập: %w", err)
		}
		if _, _, _, _, ok := a.proxyClient.SessionSnapshot(); !ok {
			return nil, fmt.Errorf("vui lòng đăng nhập (tài khoản bắt buộc trên máy chủ)")
		}
	}
	if params.VoiceID == "" || params.ModelID == "" {
		return nil, fmt.Errorf("voice ID và model ID không được để trống")
	}

	paras := webview2bridge.SplitParagraphs(params.Text)
	if len(paras) == 0 {
		return nil, fmt.Errorf("không có đoạn văn nào để xử lý")
	}

	params.MaxWorkers = a.resolveMaxWorkers()
	params.Speed = webview2bridge.ClampTTSSpeed(params.Speed)
	params.Stability = clamp01(params.Stability)
	params.SimilarityBoost = clamp01(params.SimilarityBoost)
	params.Style = clamp01(params.Style)
	if params.LanguageCode == "" {
		params.LanguageCode = "en"
	}
	if params.OutputDir == "" {
		params.OutputDir = outputdir.BesideExecutable()
	}
	if err := os.MkdirAll(params.OutputDir, 0o700); err != nil {
		return nil, err
	}
	batchDir, err := outputname.NextBatchSubdir(params.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("tạo thư mục lô xuất: %w", err)
	}
	fileStem := outputname.SanitizeStem(params.OutputFilePrefix)

	// Dựng danh sách chunk phẳng (chung cho mọi đoạn) — ID global tăng dần liên
	// tục, GroupID = chỉ số đoạn. File chunk tạm: _pNNN_cMMM.mp3 trong batchDir.
	var chunks []webview2bridge.Chunk
	var allPieces []string
	paraChunkCount := make([]int, len(paras))
	globalID := 0
	for pi, para := range paras {
		pieces := webview2bridge.ChunkTextForTTS(para, 600)
		paraChunkCount[pi] = len(pieces)
		for ci, t := range pieces {
			outName := fmt.Sprintf("_p%03d_c%03d.mp3", pi+1, ci)
			chunks = append(chunks, webview2bridge.Chunk{
				ID:         globalID,
				GroupID:    pi,
				Text:       t,
				OutputPath: filepath.Join(batchDir, outName),
			})
			allPieces = append(allPieces, t)
			globalID++
		}
	}
	if len(chunks) == 0 {
		return nil, fmt.Errorf("không có nội dung để xử lý")
	}

	var quotaNeed int64
	for _, p := range allPieces {
		quotaNeed += int64(utf8.RuneCountInString(p))
	}
	if a.commercialAuth && quotaNeed > 0 {
		if err := a.proxyClient.CommercialQuotaCheck(context.Background(), quotaNeed); err != nil {
			return nil, err
		}
	}

	diaglog.Append("generate_paragraphs_start", map[string]any{
		"version": buildinfo.AppVersion, "paragraphs": len(paras),
		"chunks": len(chunks), "batchDir": batchDir, "workers": params.MaxWorkers,
	})

	cfg := webview2bridge.Config{
		NumWorkers:       params.MaxWorkers,
		SharedProxyLease: buildinfo.SharedProxyLease,
		MaxChars:         600,
		OutputDir:        batchDir,
		Voice:            params.VoiceID,
		Model:            params.ModelID,
		LanguageCode:     params.LanguageCode,
		Speed:            params.Speed,
		Stability:        params.Stability,
		SimilarityBoost:  params.SimilarityBoost,
		Style:            params.Style,
		UseSpeakerBoost:  params.UseSpeakerBoost,
		ExportSRT:        false,
		Provider:         a.newProvider(),
		Emit:             a.poolEmit(),
	}
	chunkResults, err := webview2bridge.RunChunks(context.Background(), chunks, cfg)
	if err != nil {
		diaglog.Append("generate_paragraphs_run_error", map[string]any{"error": err.Error()})
		return nil, err
	}

	byPara := make(map[int][]webview2bridge.ChunkResult, len(paras))
	for _, r := range chunkResults {
		byPara[r.GroupID] = append(byPara[r.GroupID], r)
	}

	out := make([]tts.JobResult, 0, len(paras))
	okParas := 0
	for pi := 0; pi < len(paras); pi++ {
		rs := byPara[pi]
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })

		seq := fmt.Sprintf("%03d", pi+1)
		name := seq + ".mp3"
		if fileStem != "" {
			name = fileStem + "_" + seq + ".mp3"
		}
		finalPath := filepath.Join(batchDir, name)

		allOK := len(rs) == paraChunkCount[pi] && len(rs) > 0
		var failMsg string
		for _, r := range rs {
			if !r.OK {
				allOK = false
				failMsg = r.Message
				break
			}
		}
		if !allOK {
			if failMsg == "" {
				failMsg = "thiếu chunk"
			}
			out = append(out, tts.JobResult{
				ID: pi, OK: false,
				Message: fmt.Sprintf("đoạn %d lỗi: %s", pi+1, failMsg),
				Output:  finalPath,
			})
			a.emit(ProgressPayload{
				Phase: "error", JobID: pi, WorkerID: -1,
				Message: fmt.Sprintf("Đoạn %d/%d lỗi — %s", pi+1, len(paras), webview2bridge.FriendlyChunkSummary(false, failMsg)),
			})
			continue
		}

		bytes, mErr := webview2bridge.MergeChunks(rs, finalPath)
		if mErr != nil {
			out = append(out, tts.JobResult{
				ID: pi, OK: false,
				Message: fmt.Sprintf("đoạn %d ghép lỗi: %s", pi+1, mErr.Error()),
				Output:  finalPath,
			})
			continue
		}
		removePerLineChunksAfterMerge(rs, finalPath)
		okParas++
		out = append(out, tts.JobResult{
			ID: pi, OK: true,
			Message: fmt.Sprintf("%s (%d bytes)", name, bytes),
			Output:  finalPath,
		})
		a.emit(ProgressPayload{
			Phase: "done", JobID: pi, WorkerID: -1,
			Message: fmt.Sprintf("Đoạn %d/%d → %s", pi+1, len(paras), name),
		})
	}

	if a.commercialAuth {
		var quotaConsumed int64
		for _, r := range chunkResults {
			if r.ID >= 0 && r.ID < len(allPieces) && r.OK {
				quotaConsumed += int64(utf8.RuneCountInString(allPieces[r.ID]))
			}
		}
		if quotaConsumed > 0 {
			if err := a.proxyClient.CommercialConsumeChars(context.Background(), quotaConsumed); err != nil {
				a.emit(ProgressPayload{
					Phase: "error", JobID: -1, WorkerID: -1,
					Message: "Cảnh báo đồng bộ hạn mức ký tự: " + err.Error(),
				})
			}
		}
	}

	diaglog.Append("generate_paragraphs_done", map[string]any{
		"paragraphs_ok": okParas, "paragraphs_total": len(paras),
	})
	return out, nil
}

// GenerateDialogue: tạo hội thoại nhiều giọng. Văn bản dạng "#1 …", "#2 …";
// mỗi lượt nói dùng VoiceID của người nói tương ứng (params.Speakers). Mọi chunk
// của mọi lượt chạy chung 1 pool đa luồng (giống mode đoạn) rồi GHÉP theo thứ tự
// thành MỘT file hội thoại liền mạch.
func (a *App) GenerateDialogue(params GenerateParams) ([]tts.JobResult, error) {
	if a.commercialAuth {
		if err := a.proxyClient.EnsureFreshToken(context.Background()); err != nil {
			return nil, fmt.Errorf("phiên đăng nhập: %w", err)
		}
		if _, _, _, _, ok := a.proxyClient.SessionSnapshot(); !ok {
			return nil, fmt.Errorf("vui lòng đăng nhập (tài khoản bắt buộc trên máy chủ)")
		}
	}
	if params.ModelID == "" {
		return nil, fmt.Errorf("model ID không được để trống")
	}

	segs := webview2bridge.SplitDialogue(params.Text)
	if len(segs) == 0 {
		return nil, fmt.Errorf("cần định dạng hội thoại: mỗi lượt bắt đầu bằng #1, #2…")
	}

	voiceFor := make(map[int]string)
	for _, s := range params.Speakers {
		if v := strings.TrimSpace(s.VoiceID); v != "" {
			voiceFor[s.Key] = v
		}
	}
	var missing []int
	seenMissing := make(map[int]bool)
	for _, seg := range segs {
		if voiceFor[seg.Speaker] == "" && !seenMissing[seg.Speaker] {
			seenMissing[seg.Speaker] = true
			missing = append(missing, seg.Speaker)
		}
	}
	if len(missing) > 0 {
		sort.Ints(missing)
		parts := make([]string, len(missing))
		for i, m := range missing {
			parts[i] = "#" + strconv.Itoa(m)
		}
		return nil, fmt.Errorf("chưa cấu hình giọng cho người nói: %s", strings.Join(parts, ", "))
	}

	params.MaxWorkers = a.resolveMaxWorkers()
	params.Speed = webview2bridge.ClampTTSSpeed(params.Speed)
	params.Stability = clamp01(params.Stability)
	params.SimilarityBoost = clamp01(params.SimilarityBoost)
	params.Style = clamp01(params.Style)
	if params.LanguageCode == "" {
		params.LanguageCode = "en"
	}
	if params.OutputDir == "" {
		params.OutputDir = outputdir.BesideExecutable()
	}
	if err := os.MkdirAll(params.OutputDir, 0o700); err != nil {
		return nil, err
	}
	batchDir, err := outputname.NextBatchSubdir(params.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("tạo thư mục lô xuất: %w", err)
	}
	fileStem := outputname.SanitizeStem(params.OutputFilePrefix)

	// Chunk phẳng theo thứ tự lượt; ID global tăng dần = thứ tự hội thoại,
	// GroupID = chỉ số lượt, Voice = giọng của người nói lượt đó.
	var chunks []webview2bridge.Chunk
	var allPieces []string
	segChunkCount := make([]int, len(segs))
	globalID := 0
	for si, seg := range segs {
		pieces := webview2bridge.ChunkTextForTTS(seg.Text, 600)
		segChunkCount[si] = len(pieces)
		for ci, t := range pieces {
			outName := fmt.Sprintf("_s%03d_c%03d.mp3", si+1, ci)
			chunks = append(chunks, webview2bridge.Chunk{
				ID:         globalID,
				GroupID:    si,
				Voice:      voiceFor[seg.Speaker],
				Text:       t,
				OutputPath: filepath.Join(batchDir, outName),
			})
			allPieces = append(allPieces, t)
			globalID++
		}
	}
	if len(chunks) == 0 {
		return nil, fmt.Errorf("không có nội dung để xử lý")
	}

	var quotaNeed int64
	for _, p := range allPieces {
		quotaNeed += int64(utf8.RuneCountInString(p))
	}
	if a.commercialAuth && quotaNeed > 0 {
		if err := a.proxyClient.CommercialQuotaCheck(context.Background(), quotaNeed); err != nil {
			return nil, err
		}
	}

	// Voice mặc định (fallback nếu chunk không set) = giọng lượt đầu.
	defaultVoice := voiceFor[segs[0].Speaker]

	diaglog.Append("generate_dialogue_start", map[string]any{
		"version": buildinfo.AppVersion, "segments": len(segs),
		"chunks": len(chunks), "speakers": len(voiceFor), "batchDir": batchDir,
		"workers": params.MaxWorkers,
	})

	cfg := webview2bridge.Config{
		NumWorkers:       params.MaxWorkers,
		SharedProxyLease: buildinfo.SharedProxyLease,
		MaxChars:         600,
		OutputDir:        batchDir,
		Voice:            defaultVoice,
		Model:            params.ModelID,
		LanguageCode:     params.LanguageCode,
		Speed:            params.Speed,
		Stability:        params.Stability,
		SimilarityBoost:  params.SimilarityBoost,
		Style:            params.Style,
		UseSpeakerBoost:  params.UseSpeakerBoost,
		ExportSRT:        false,
		Provider:         a.newProvider(),
		Emit:             a.poolEmit(),
	}
	chunkResults, err := webview2bridge.RunChunks(context.Background(), chunks, cfg)
	if err != nil {
		diaglog.Append("generate_dialogue_run_error", map[string]any{"error": err.Error()})
		return nil, err
	}

	bySeg := make(map[int][]webview2bridge.ChunkResult, len(segs))
	for _, r := range chunkResults {
		bySeg[r.GroupID] = append(bySeg[r.GroupID], r)
	}

	out := make([]tts.JobResult, 0, len(segs)+1)
	allOK := len(chunkResults) > 0
	for si := range segs {
		rs := bySeg[si]
		segOK := len(rs) == segChunkCount[si] && len(rs) > 0
		var failMsg string
		for _, r := range rs {
			if !r.OK {
				segOK = false
				failMsg = r.Message
				break
			}
		}
		if !segOK {
			allOK = false
		}
		msg := fmt.Sprintf("#%d — %d phần", segs[si].Speaker, len(rs))
		if !segOK {
			msg = fmt.Sprintf("#%d lỗi: %s", segs[si].Speaker, failMsg)
		}
		out = append(out, tts.JobResult{ID: si, OK: segOK, Message: msg})
		a.emit(ProgressPayload{
			Phase: phaseFor(segOK), JobID: si, WorkerID: -1,
			Message: fmt.Sprintf("Lượt %d/%d (người nói #%d) — %s",
				si+1, len(segs), segs[si].Speaker, webview2bridge.FriendlyChunkSummary(segOK, failMsg)),
		})
	}

	if allOK {
		mergeStem := fileStem
		if mergeStem == "" {
			mergeStem = "hoithoai"
		}
		mergeFile := mergeStem + ".mp3"
		mergedPath := filepath.Join(batchDir, mergeFile)
		bytes, mErr := webview2bridge.MergeChunks(chunkResults, mergedPath)
		if mErr != nil {
			a.emit(ProgressPayload{
				Phase: "error", JobID: -1, WorkerID: -1,
				Message: "Ghép hội thoại lỗi: " + mErr.Error(),
			})
		} else {
			removePerLineChunksAfterMerge(chunkResults, mergedPath)
			out = append(out, tts.JobResult{
				ID: -1, OK: true,
				Message: fmt.Sprintf("%s (%d bytes)", mergeFile, bytes),
				Output:  mergedPath,
			})
			a.emit(ProgressPayload{
				Phase: "merge", JobID: -1, WorkerID: -1,
				Message: fmt.Sprintf("Đã ghép hội thoại %d lượt → %s (%.2f MB)",
					len(segs), mergeFile, float64(bytes)/(1024*1024)),
			})
		}
	}

	if a.commercialAuth {
		var quotaConsumed int64
		for _, r := range chunkResults {
			if r.ID >= 0 && r.ID < len(allPieces) && r.OK {
				quotaConsumed += int64(utf8.RuneCountInString(allPieces[r.ID]))
			}
		}
		if quotaConsumed > 0 {
			if err := a.proxyClient.CommercialConsumeChars(context.Background(), quotaConsumed); err != nil {
				a.emit(ProgressPayload{
					Phase: "error", JobID: -1, WorkerID: -1,
					Message: "Cảnh báo đồng bộ hạn mức ký tự: " + err.Error(),
				})
			}
		}
	}

	diaglog.Append("generate_dialogue_done", map[string]any{
		"segments": len(segs), "merged": allOK,
	})
	return out, nil
}

// phaseFor trả phase tiến độ theo trạng thái OK.
func phaseFor(ok bool) string {
	if ok {
		return "done"
	}
	return "error"
}

// GetSpeakers đọc bảng người nói đã lưu (mode hội thoại).
func (a *App) GetSpeakers() []DialogueSpeaker {
	c, _ := appconfig.Load()
	out := make([]DialogueSpeaker, 0, len(c.Speakers))
	for _, s := range c.Speakers {
		out = append(out, DialogueSpeaker{Key: s.Key, VoiceID: s.VoiceID, Note: s.Note})
	}
	return out
}

// SaveSpeakers lưu toàn bộ bảng người nói (ghi nhớ giữa các phiên).
func (a *App) SaveSpeakers(list []DialogueSpeaker) error {
	conv := make([]appconfig.Speaker, 0, len(list))
	for _, s := range list {
		if strings.TrimSpace(s.VoiceID) == "" {
			continue
		}
		conv = append(conv, appconfig.Speaker{Key: s.Key, VoiceID: strings.TrimSpace(s.VoiceID), Note: strings.TrimSpace(s.Note)})
	}
	return appconfig.SetSpeakers(conv)
}

// AppConfigDTO — cấu hình ghi nhớ trả về frontend.
type AppConfigDTO struct {
	OutputDir string `json:"outputDir"`
}

// GetAppConfig đọc cấu hình đã lưu (thư mục output ghi nhớ giữa các phiên).
func (a *App) GetAppConfig() AppConfigDTO {
	c, _ := appconfig.Load()
	return AppConfigDTO{OutputDir: c.OutputDir}
}

// SaveOutputDir lưu thư mục output để mở lại ở lần chạy sau.
func (a *App) SaveOutputDir(dir string) error {
	return appconfig.SetOutputDir(strings.TrimSpace(dir))
}

// prefixID chỉ log vài ký tự đầu voice id (tránh nhật ký dài; đủ đối chiếu).
func prefixID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

// GetCommercialAuthRequired — true khi Vercel bật COMMERCIAL_AUTH (desktop cần đăng nhập).
func (a *App) GetCommercialAuthRequired() bool {
	return a.commercialAuth
}

// GetSessionEmail — rỗng nếu chưa đăng nhập.
func (a *App) GetSessionEmail() string {
	if !a.commercialAuth {
		return ""
	}
	_, _, _, email, ok := a.proxyClient.SessionSnapshot()
	if !ok {
		return ""
	}
	return email
}

// GetCommercialQuota — đọc hạn ký tự (POST quota-check need_chars=0). Chỉ khi commercial + đã đăng nhập.
func (a *App) GetCommercialQuota() (CommercialQuotaDTO, error) {
	var out CommercialQuotaDTO
	if !a.commercialAuth {
		out.Unlimited = true
		return out, nil
	}
	if _, _, _, _, ok := a.proxyClient.SessionSnapshot(); !ok {
		return out, fmt.Errorf("chưa đăng nhập")
	}
	if err := a.proxyClient.EnsureFreshToken(context.Background()); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	snap, err := a.proxyClient.CommercialQuotaFetch(ctx)
	if err != nil {
		return out, err
	}
	out.Unlimited = snap.Unlimited
	out.CharsUsed = snap.CharsUsed
	out.MaxChars = snap.MaxChars
	out.Remaining = snap.Remaining
	return out, nil
}

// Login — email/password Supabase (server /api/auth/login).
func (a *App) Login(email, password string) error {
	if !a.commercialAuth {
		return fmt.Errorf("máy chủ không yêu cầu đăng nhập")
	}
	email = strings.TrimSpace(email)
	if email == "" || password == "" {
		return fmt.Errorf("email và mật khẩu không được để trống")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sec := os.Getenv("ELEVENFLOW_APP_SECRET")
	if sec == "" {
		sec = proxyserver.DefaultAppSecret
	}
	lr, err := proxyserver.PasswordLogin(ctx, a.proxyClient.ServerURL(), sec, email, password, a.deviceFingerprint)
	if err != nil {
		return err
	}
	exp := lr.ExpiresIn
	if exp <= 0 {
		exp = 3600
	}
	a.proxyClient.ApplyCommercialSession(lr.AccessToken, lr.RefreshToken, exp, lr.UserEmail)
	a.proxyClient.SetDeviceFingerprint(a.deviceFingerprint)
	return nil
}

// GetSavedLoginPrefs — email + mật khẩu đã ghi nhớ (chỉ điền form), không phải JWT.
func (a *App) GetSavedLoginPrefs() SavedLoginPrefs {
	email, pass, ok := authlocal.LoadLoginPrefs(a.deviceFingerprint)
	return SavedLoginPrefs{Email: email, Password: pass, Saved: ok}
}

// SaveLoginPrefs lưu email + mật khẩu mã hóa trên máy (user chọn «Ghi nhớ»).
func (a *App) SaveLoginPrefs(email, password string) error {
	return authlocal.SaveLoginPrefs(a.deviceFingerprint, email, password)
}

// ClearSavedLoginPrefs xóa file ghi nhớ form.
func (a *App) ClearSavedLoginPrefs() error {
	return authlocal.ClearLoginPrefs()
}

// Logout xóa JWT trong bộ nhớ (không xóa ghi nhớ form trừ khi user tự bỏ chọn).
func (a *App) Logout() {
	a.proxyClient.ClearCommercialSession()
	a.proxyClient.SetDeviceFingerprint(a.deviceFingerprint)
	// Xóa session.blob cũ (bản trước lưu JWT) để không còn file nhạy cảm sót lại.
	_ = authlocal.New(a.deviceFingerprint).Clear()
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// removePerLineChunksAfterMerge xóa các MP3 từng dòng sau khi đã ghép xong;
// không xóa mergedPath. Trả số file xóa được (0 nếu lỗi hoặc không có).
func removePerLineChunksAfterMerge(results []webview2bridge.ChunkResult, mergedPath string) int {
	absMerged, err := filepath.Abs(filepath.Clean(mergedPath))
	if err != nil {
		absMerged = filepath.Clean(mergedPath)
	}
	n := 0
	for _, r := range results {
		if !r.OK || r.Output == "" {
			continue
		}
		absOut, err := filepath.Abs(filepath.Clean(r.Output))
		if err != nil {
			absOut = filepath.Clean(r.Output)
		}
		if absOut == absMerged {
			continue
		}
		if err := os.Remove(r.Output); err == nil {
			n++
		}
	}
	return n
}
