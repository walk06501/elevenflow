package webview2bridge

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"elevenflow/internal/diaglog"
)

// SessionPool là mô hình thay thế cho Run/RunChunks: thay vì spawn N worker
// MỚI cho MỖI HTTP request rồi teardown hết khi request xong (chi phí mỗi
// lần: acquire proxy + mở WebView2 + navigate + giải hCaptcha — vài giây tới
// hàng chục giây), SessionPool giữ 1 số lượng session CỐ ĐỊNH sống XUYÊN
// SUỐT nhiều request, chỉ đóng cửa sổ WebView2 của 1 session khi:
//
//  1. Bị lỗi thật (401 unusual_activity / lỗi mạng transient) — dùng lại
//     nguyên vẹn processChunkWithRetry/rotateAndRespawn đã có sẵn ở
//     worker.go, đường lỗi này BẮT BUỘC đổi IP (xem lý do ở đó).
//  2. Idle quá lâu (IdleCloseAfter) — CHỈ đóng cửa sổ WebView2 (giải phóng
//     CPU/RAM Chromium) chứ KHÔNG đổi IP/lease: quyết định sản phẩm rõ ràng
//     là "còn dùng tốt thì cứ giữ, chỉ đổi khi bị ban" — đổi IP không cần
//     thiết chỉ tổ làm chậm request tiếp theo (phải acquire+navigate+giải
//     captcha lại từ đầu) mà không giải quyết gì thêm.
//
// Vì nhiều request khác nhau (có thể khác model/ngôn ngữ/tốc độ/giọng) giờ
// dùng chung 1 nhóm session, mỗi Chunk gửi vào đây PHẢI có Params set (xem
// Chunk.Params, TTSParams) — không còn Pool.cfg chung cho cả batch nữa.
type SessionPool struct {
	cfg  SessionPoolConfig
	pool *Pool // chỉ dùng cho proxyProvider/requestFor — KHÔNG có config TTS cố định

	jobs   chan sessionJob
	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup

	activeSessions atomic.Int32 // đang có WebView2 mở (không tính lúc idle-closed)

	// chunkCache: kết quả chunk ĐÃ THÀNH CÔNG của 1 JobID (web-portal gửi
	// job_nodes.id), để 1 request retry (do 1 vài chunk khác lỗi) không phải
	// làm lại TOÀN BỘ text — chỉ chunk nào chưa có trong cache mới thật sự
	// chạy lại. Xem doc comment SynthesizeRequest.JobID (handler.go) cho bối
	// cảnh đầy đủ. Dọn theo TTL (jobChunkCacheTTL) bằng goroutine nền, không
	// phải theo per-request cleanup, vì 1 JobID có thể cần cache SỐNG QUA
	// NHIỀU lần gọi /synthesize riêng biệt (mỗi lần retry của web-portal là
	// 1 request HTTP mới).
	chunkCacheMu sync.Mutex
	chunkCache   map[string]*jobChunkCache
}

type jobChunkCache struct {
	results     map[int]cachedChunk
	lastTouched time.Time
}

// cachedChunk giữ CẢ bytes audio thật (không chỉ ChunkResult.Output — path
// đó trỏ vào tmpDir riêng của request cũ, đã bị os.RemoveAll dọn sạch ngay
// sau khi request đó trả lời xong, xem handler.go's "defer
// os.RemoveAll(tmpDir)"). Không cache bytes thì cache path vô dụng — request
// retry sau có tmpDir MỚI, phải ghi lại bytes vào đường dẫn mới đó.
type cachedChunk struct {
	result ChunkResult
	data   []byte
}

// jobChunkCacheTTL: đủ dài để sống qua toàn bộ chuỗi retry thật của 1 job
// (web-portal: 10 attempt × tối đa vài phút/attempt — xem
// eleven_visibility_timeout_seconds), nhưng không giữ mãi mãi tránh rò rỉ bộ
// nhớ cho job không bao giờ retry lại (đa số job — chỉ job có chunk lỗi mới
// cần cache này).
const jobChunkCacheTTL = 30 * time.Minute

// SessionPoolConfig cấu hình SessionPool tại thời điểm khởi động server.
type SessionPoolConfig struct {
	NumSessions int           // số session cố định — nên bằng MaxConcurrent×MaxWorkers hiện tại để giữ nguyên trần CPU/proxy
	Provider    ProxyProvider // bắt buộc — NordVPN/PIA/Surfshark/MultiVPNProvider...
	DataRoot    string        // thư mục gốc profile WebView2, sống suốt đời server (không phải per-request)
	Visible     bool

	// IdleCloseAfter: sau chừng này không có job mới, đóng cửa sổ WebView2
	// để giải phóng CPU/RAM (nhưng giữ nguyên lease/tunnel — xem doc comment
	// SessionPool). 0 → mặc định 3 phút.
	IdleCloseAfter time.Duration

	// JobQueueSize: buffer channel jobs — request bị block ở Submit khi hàng
	// đợi đầy (áp lực ngược tự nhiên thay vì OOM nếu traffic v ượt xa NumSessions).
	// 0 → mặc định NumSessions*8.
	JobQueueSize int
}

type sessionJob struct {
	ctx    context.Context
	chunk  Chunk
	emit   EmitFn
	total  int
	result chan ChunkResult
}

// NewSessionPool khởi tạo NumSessions goroutine session ngay (nhẹ — mỗi
// goroutine chỉ chờ ở channel, CHƯA mở WebView2/proxy nào). Việc mở
// WebView2 + acquire proxy chỉ xảy ra LAZY, khi session đó nhận job ĐẦU
// TIÊN — cố tình không "làm ấm" toàn bộ pool ngay lúc server khởi động, vì
// nếu chưa có traffic thì NumSessions cửa sổ Chromium + tunnel mở sẵn chỉ
// tổ tốn CPU/RAM liên tục cho không, đi ngược yêu cầu "ít mất CPU nhất".
// Cái giá đánh đổi: request ĐẦU TIÊN sau khi server khởi động (hoặc sau khi
// 1 session bị idle-close) phải chịu đúng 1 lần cold-spawn — các request
// sau đó, khi pool đã "ấm" nhờ được dùng liên tục, không còn trả giá này
// nữa (khác hẳn mô hình Run/RunChunks cũ trả giá cold-spawn ở MỌI request).
func NewSessionPool(cfg SessionPoolConfig) (*SessionPool, error) {
	if cfg.Provider == nil {
		return nil, fmt.Errorf("SessionPool: Provider bắt buộc")
	}
	if cfg.NumSessions < 1 {
		cfg.NumSessions = 1
	}
	if cfg.IdleCloseAfter <= 0 {
		cfg.IdleCloseAfter = 3 * time.Minute
	}
	if cfg.JobQueueSize <= 0 {
		cfg.JobQueueSize = cfg.NumSessions * 8
	}
	if cfg.DataRoot == "" {
		cfg.DataRoot = filepath.Join(os.TempDir(), "elevenflow-session-pool-profiles")
	}
	if err := os.MkdirAll(cfg.DataRoot, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir session pool data root: %w", err)
	}

	sp := &SessionPool{
		cfg: cfg,
		// pool chỉ để tái dùng proxyProvider + requestFor(chunk) từ worker.go —
		// totalChunks/emitFn ở đây không dùng tới (mỗi job tự mang emit/total
		// riêng qua overrideEmit/overrideTotal, xem worker.go).
		pool:   &Pool{proxyProvider: cfg.Provider},
		jobs:   make(chan sessionJob, cfg.JobQueueSize),
		closed: make(chan struct{}),
	}

	diaglog.Append("session_pool_start", map[string]any{
		"numSessions":    cfg.NumSessions,
		"idleCloseAfter": cfg.IdleCloseAfter.String(),
	})

	for i := 0; i < cfg.NumSessions; i++ {
		sp.wg.Add(1)
		go sp.sessionLoop(i)
	}
	sp.chunkCache = make(map[string]*jobChunkCache)
	go sp.chunkCacheJanitor()
	return sp, nil
}

// chunkCacheJanitor dọn jobChunkCache định kỳ — job nào không được "chạm"
// (Synthesize gọi lại với cùng JobID) trong jobChunkCacheTTL thì coi như đã
// xong (thành công hẳn) hoặc bị bỏ (khách huỷ/hết attempt) và không cần cache
// nữa. Chạy tới khi sp.closed.
func (sp *SessionPool) chunkCacheJanitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-sp.closed:
			return
		case <-ticker.C:
			sp.chunkCacheMu.Lock()
			cutoff := time.Now().Add(-jobChunkCacheTTL)
			evicted := 0
			for jobID, jc := range sp.chunkCache {
				if jc.lastTouched.Before(cutoff) {
					delete(sp.chunkCache, jobID)
					evicted++
				}
			}
			remaining := len(sp.chunkCache)
			sp.chunkCacheMu.Unlock()
			if evicted > 0 {
				log.Printf("[chunk-cache] janitor: evicted %d stale job(s), %d remaining", evicted, remaining)
			}
		}
	}
}

// Synthesize chunk hoá text rồi chạy qua SessionPool — chữ ký tương đương
// webview2bridge.Run, để handler.go đổi qua lại giữa 2 đường (persistent
// pool bật/tắt qua config) mà không phải viết lại phần chunk/merge xung quanh.
//
// jobID (optional — xem SynthesizeRequest.JobID, handler.go): khi khác rỗng,
// chunk nào đã THÀNH CÔNG ở 1 lần gọi TRƯỚC ĐÓ cùng jobID được phục vụ từ
// cache thay vì chạy lại — 1 request retry (do 1-2 chunk lỗi, các chunk khác
// đã xong) giờ chỉ thật sự tốn phiên trình duyệt cho đúng phần còn thiếu.
func (sp *SessionPool) Synthesize(ctx context.Context, jobID string, text string, maxChars int, outputDir, outputStem string, params TTSParams, voice string, emit EmitFn) ([]ChunkResult, error) {
	if err := ValidateLanguageForModel(params.Model, params.LanguageCode); err != nil {
		return nil, err
	}
	maxChunk := maxChars
	if maxChunk <= 0 || maxChunk > defaultMaxChunkChars {
		maxChunk = defaultMaxChunkChars
	}
	pieces := ChunkTextForTTS(text, maxChunk)
	if len(pieces) == 0 {
		return nil, fmt.Errorf("không có nội dung để xử lý")
	}
	chunks := make([]Chunk, len(pieces))
	for i, t := range pieces {
		outName := fmt.Sprintf("chunk_%04d.mp3", i)
		if stem := strings.TrimSpace(outputStem); stem != "" {
			outName = fmt.Sprintf("%s_%04d.mp3", stem, i+1)
		}
		p := params
		chunks[i] = Chunk{
			ID:         i,
			Voice:      voice,
			Text:       t,
			OutputPath: filepath.Join(outputDir, outName),
			Params:     &p,
		}
	}

	if strings.TrimSpace(jobID) == "" {
		return sp.Submit(ctx, chunks, emit)
	}

	// Tách chunk đã có cache (ghi thẳng bytes vào outputDir MỚI của request
	// này, không chạy lại) khỏi chunk còn phải chạy thật.
	results := make([]ChunkResult, len(chunks))
	hit := make([]bool, len(chunks))
	var toSubmit []Chunk
	sp.chunkCacheMu.Lock()
	jc := sp.chunkCache[jobID]
	if jc != nil {
		jc.lastTouched = time.Now()
	}
	sp.chunkCacheMu.Unlock()
	if jc != nil {
		for i, c := range chunks {
			jc2, ok := jc.results[c.ID]
			if !ok {
				toSubmit = append(toSubmit, c)
				continue
			}
			if err := os.WriteFile(c.OutputPath, jc2.data, 0o644); err != nil {
				// Ghi cache ra đĩa lỗi (hiếm — disk full?) — coi như cache
				// miss, chạy lại chunk này cho chắc thay vì fail cả request.
				toSubmit = append(toSubmit, c)
				continue
			}
			r := jc2.result
			r.Output = c.OutputPath
			results[i] = r
			hit[i] = true
			emit(r.WorkerID, c.ID, "tts", "Đã có sẵn từ lần thử trước, dùng lại.", -1, len(chunks))
		}
	} else {
		toSubmit = chunks
	}

	if len(toSubmit) < len(chunks) {
		log.Printf("[chunk-cache] job=%s: %d/%d chunk phục vụ từ cache, chạy lại %d",
			jobID, len(chunks)-len(toSubmit), len(chunks), len(toSubmit))
	}

	if len(toSubmit) > 0 {
		submitted, err := sp.Submit(ctx, toSubmit, emit)
		if err != nil {
			return nil, err
		}
		bySubmitID := make(map[int]ChunkResult, len(submitted))
		for _, r := range submitted {
			bySubmitID[r.ID] = r
		}
		for i, c := range chunks {
			if hit[i] {
				continue
			}
			if r, ok := bySubmitID[c.ID]; ok {
				results[i] = r
			}
		}
	}

	allOK := true
	for _, r := range results {
		if !r.OK {
			allOK = false
			break
		}
	}

	if allOK {
		// Cả job xong sạch trong lần gọi này — không có gì để cache (mọi
		// chunk cache hit đã lưu sẵn rồi; chunk mới chạy cũng thành công
		// luôn, không cần lưu lại phòng retry vì sẽ không retry). Dọn luôn
		// nếu janitor lỡ để sót entry cũ từ 1 lần thử trước đó của job này.
		sp.chunkCacheMu.Lock()
		delete(sp.chunkCache, jobID)
		sp.chunkCacheMu.Unlock()
	} else if len(toSubmit) > 0 {
		// Còn chunk lỗi (sẽ retry ở lần gọi request SAU) — lưu lại bytes của
		// những chunk MỚI vừa thành công trong lần này, để lần retry sau chỉ
		// còn phải làm lại đúng phần còn lỗi.
		newlyOK := make(map[int]cachedChunk)
		for i, c := range chunks {
			if hit[i] || !results[i].OK {
				continue
			}
			if data, readErr := os.ReadFile(results[i].Output); readErr == nil {
				newlyOK[c.ID] = cachedChunk{result: results[i], data: data}
			}
		}
		if len(newlyOK) > 0 {
			sp.chunkCacheMu.Lock()
			jc := sp.chunkCache[jobID]
			if jc == nil {
				jc = &jobChunkCache{results: make(map[int]cachedChunk)}
				sp.chunkCache[jobID] = jc
			}
			for id, cc := range newlyOK {
				jc.results[id] = cc
			}
			jc.lastTouched = time.Now()
			sp.chunkCacheMu.Unlock()
		}
	}

	return results, nil
}

// Submit đẩy toàn bộ chunks của 1 request vào hàng đợi chung, đợi đủ kết
// quả rồi trả về theo ĐÚNG thứ tự đã truyền vào (không cần sort lại như
// executeChunks vì mỗi chunk có kênh kết quả riêng, không lẫn giữa request).
func (sp *SessionPool) Submit(ctx context.Context, chunks []Chunk, emit EmitFn) ([]ChunkResult, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("không có nội dung để xử lý")
	}
	if emit == nil {
		emit = func(int, int, string, string, int, int) {}
	}
	total := len(chunks)
	resultChans := make([]chan ChunkResult, len(chunks))
	for i, c := range chunks {
		if c.Params == nil {
			return nil, fmt.Errorf("chunk %d thiếu Params — bắt buộc khi chạy qua SessionPool", c.ID)
		}
		rc := make(chan ChunkResult, 1)
		resultChans[i] = rc
		job := sessionJob{ctx: ctx, chunk: c, emit: emit, total: total, result: rc}
		select {
		case sp.jobs <- job:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-sp.closed:
			return nil, fmt.Errorf("session pool đang tắt")
		}
	}

	results := make([]ChunkResult, len(chunks))
	for i, rc := range resultChans {
		select {
		case r := <-rc:
			results[i] = r
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return results, nil
}

// Close dừng nhận job mới, đợi mọi session hiện có xử lý xong job đang cầm
// (nếu có) rồi teardown WebView2 + release lease sạch sẽ. Gọi khi server
// shutdown (main.go), tương tự defer cleanup của executeChunks nhưng chạy
// 1 lần cho cả pool thay vì mỗi request.
func (sp *SessionPool) Close() {
	sp.once.Do(func() { close(sp.closed) })
	sp.wg.Wait()
	if sd, ok := sp.cfg.Provider.(interface{ Shutdown() }); ok {
		sd.Shutdown()
	}
	_ = os.RemoveAll(sp.cfg.DataRoot)
}

// ActiveSessions trả số session ĐANG mở WebView2 (không tính session đang
// idle-closed chờ job) — dùng cho /health.
func (sp *SessionPool) ActiveSessions() int32 { return sp.activeSessions.Load() }

// sessionLoop là vòng đời 1 session: mở WebView2 ngay từ đầu, xử lý job lần
// lượt (chunk nào tới trước làm trước, không phân biệt job thuộc request
// nào), tự đóng cửa sổ khi rảnh quá lâu, tự mở lại (dùng NGUYÊN lease cũ,
// không đổi IP) khi có job mới tới.
//
// Khác với worker.run() (đường Run/RunChunks cũ): ở đó 1 worker "chết" (thoát
// goroutine) khi respawn thất bại liên tục, vì trong mô hình cũ LUÔN CÒN
// worker khác của CÙNG request đó nhặt nốt chunk còn lại từ channel dùng
// chung của request. ở đây KHÔNG còn "worker khác của cùng request" — mỗi
// job có đúng 1 kênh kết quả, nếu session này bỏ cuộc job đó thất bại thẳng,
// không ai nhặt lại. Vì vậy sessionLoop KHÔNG BAO GIỜ thoát vì lỗi nghiệp vụ
// — chỉ thoát khi SessionPool.Close() được gọi — spawn thất bại chỉ đặt lại
// cờ "chưa mở", job kế tiếp sẽ tự thử acquire+spawn lại từ đầu (tự phục hồi
// dần, không rút bớt sức chứa pool vĩnh viễn như mô hình cũ).
func (sp *SessionPool) sessionLoop(id int) {
	defer sp.wg.Done()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := coInitializeApartment(); err != nil {
		diaglog.Append("session_com_init_failed", map[string]any{"session": id, "err": err.Error()})
		return
	}
	defer coUninitialize()

	w := newWorker(id, sp.pool, nil, nil, sp.cfg.DataRoot, sp.cfg.Visible)
	spawned := false

	teardown := func() {
		if !spawned {
			return
		}
		w.teardownWebView2()
		spawned = false
		sp.activeSessions.Add(-1)
	}
	// Đóng hẳn khi pool Close(): release lease thật (khác idle-close — xem
	// doc comment struct), không chỉ teardown cửa sổ.
	finalClose := func() {
		if spawned {
			w.teardownWebView2()
			spawned = false
			sp.activeSessions.Add(-1)
		}
		if sp.cfg.Provider != nil {
			sp.cfg.Provider.Release(w.id, w.currentLease)
		}
	}

	idleTimer := time.NewTimer(sp.cfg.IdleCloseAfter)
	defer idleTimer.Stop()

	for {
		select {
		case <-sp.closed:
			finalClose()
			return

		case <-idleTimer.C:
			teardown()
			idleTimer.Reset(sp.cfg.IdleCloseAfter)

		case job, ok := <-sp.jobs:
			if !ok {
				finalClose()
				return
			}
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}

			if job.ctx.Err() != nil {
				// Caller đã bỏ cuộc trong lúc job còn nằm trong hàng đợi — trả
				// lỗi ngay, không tốn 1 lần acquire/spawn/hCaptcha vô ích.
				job.result <- ChunkResult{
					ID: job.chunk.ID, GroupID: job.chunk.GroupID,
					Output: job.chunk.OutputPath, WorkerID: id,
					Message: job.ctx.Err().Error(),
				}
				idleTimer.Reset(sp.cfg.IdleCloseAfter)
				continue
			}

			w.overrideEmit = job.emit
			w.overrideTotal = job.total

			if !spawned {
				// QUAN TRỌNG: nếu đã từng có lease (currentLease.URL != ""),
				// đây là thức dậy sau idle-close — KHÔNG được gọi lại Acquire().
				// Với các provider WireGuard (Nord/PIA/Surfshark), Acquire() luôn
				// tạo 1 tunnel MỚI hoàn toàn; gọi lại ở đây trong khi tunnel cũ
				// (đứng sau lease hiện có) vẫn còn sống — vì idle-close chỉ
				// teardown cửa sổ WebView2, không đụng tới lease — sẽ làm rò rỉ
				// tunnel cũ vĩnh viễn (không ai còn giữ generation của nó để
				// đóng). Idle-close nghĩa là "đóng cửa sổ, giữ nguyên IP", nên
				// thức dậy phải mở lại cửa sổ trên ĐÚNG lease đang có, chỉ
				// Acquire() thật sự khi đây là lần đầu tiên (chưa có lease nào).
				//
				// Trước khi mở lại cửa sổ trên lease cũ, xác nhận nó CÒN SỐNG:
				// giữ tunnel chạy suốt lúc idle không đảm bảo nó còn hoạt động
				// hàng phút/giờ sau (server phía kia hết hạn session, NAT
				// timeout dù đã keepalive, IP bị ban ngay lúc không dùng...).
				// Không probe thì lease chết chỉ lộ ra SAU KHI mở cửa sổ thành
				// công (mở cửa sổ không cần mạng) qua 1 lần navigation timeout
				// 2 phút trong processChunkOnce — probe biến đó thành phát
				// hiện ~6s, rồi rotate ngay như đường lỗi bình thường.
				var spawnErr error
				switch {
				case w.currentLease.URL == "":
					spawnErr = w.acquireProxyAndSpawn(job.ctx)
				case probeLeaseAlive(w.currentLease, 6*time.Second) != nil:
					spawnErr = w.rotateAndRespawn(job.ctx, job.chunk.ID, "kết nối rảnh lâu đã hết hạn")
				default:
					spawnErr = w.spawnWebView2WithRetry(job.ctx, 3)
				}
				if spawnErr != nil {
					job.result <- ChunkResult{
						ID: job.chunk.ID, GroupID: job.chunk.GroupID,
						Output: job.chunk.OutputPath, WorkerID: id,
						Message: fmt.Sprintf("không mở được phiên: %v", spawnErr),
					}
					idleTimer.Reset(sp.cfg.IdleCloseAfter)
					continue
				}
				spawned = true
				sp.activeSessions.Add(1)
			}

			res := w.processChunkWithRetry(job.ctx, job.chunk)
			job.result <- res

			// processChunkWithRetry tự rotate+respawn khi lỗi transient/bị ban;
			// w.chromium == nil nghĩa là NGAY CẢ retry rotate cũng hết sạch
			// (spawnWebView2WithRetry thất bại liên tục, vd disk full kéo dài).
			// Không thoát goroutine — chỉ đánh dấu "chưa mở" để job KẾ TIẾP tự
			// acquire+spawn lại từ đầu (xem doc comment hàm).
			if w.chromium == nil {
				spawned = false
				sp.activeSessions.Add(-1)
			}

			idleTimer.Reset(sp.cfg.IdleCloseAfter)
		}
	}
}

// probeLeaseAlive xác nhận nhanh lease còn thật sự dẫn tới mạng ngoài trước
// khi mở lại cửa sổ WebView2 trên nó sau idle-close. Chỉ dial + bắt tay TLS
// tới 1 host thật (api.ipify.org — cùng host các provider WireGuard tự dùng
// để verify tunnel lúc Acquire(), xem *_wireguard_provider.go's tryOne),
// KHÔNG cần round-trip HTTP đầy đủ — bắt tay TLS thành công đã đủ chứng minh
// gói tin đi và về được qua tunnel.
//
// Scheme http/https (PoolProvider cũ, không dùng trong production hiện tại —
// mọi VPN provider đang chạy đều trả lease "socks5://") bỏ qua probe, coi
// như còn sống, thay vì viết lại nguyên khối CONNECT-handshake của
// localproxy.go chỉ để phục vụ 1 đường không ai đang dùng.
func probeLeaseAlive(lease Lease, timeout time.Duration) error {
	u, err := url.Parse(lease.URL)
	if err != nil {
		return err
	}
	if u.Scheme != "socks5" {
		return nil
	}
	var auth *proxy.Auth
	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		auth = &proxy.Auth{User: user, Password: pass}
	}
	dialer, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: timeout})
	if err != nil {
		return err
	}
	conn, err := dialer.Dial("tcp", "api.ipify.org:443")
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "api.ipify.org"})
	return tlsConn.Handshake()
}
