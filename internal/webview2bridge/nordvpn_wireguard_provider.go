package webview2bridge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type wgServer struct {
	hostname string
	station  string
	pubHex   string
	load     int
}

type wgTunnel struct {
	dev   *device.Device
	socks *localSOCKS5Server
}

// errNordWGNoSlots: tài khoản đã dùng hết số kết nối WireGuard đồng thời
// cho phép (xem nordWGMaxConcurrentConns). Là lỗi "thử nguồn khác đi", KHÔNG
// phải "server này hỏng" — nên không được retry trong nội bộ provider.
var errNordWGNoSlots = errors.New("hết slot kết nối NordVPN WireGuard")

const (
	wgHandshakeTimeout      = 3 * time.Second
	wgProbeTimeout          = 3 * time.Second
	wgMaxAcquireAttempts    = 6
	wgServerRefreshInterval = 30 * time.Minute

	// nordWGHandshakeTimeout/nordWGMaxAcquireAttempts: NordVPN-WireGuard's
	// own pool (thousands of servers) is an order of magnitude bigger than
	// PIA's (hundreds) or Surfshark's (~140 fixed hosts), so the same
	// 6-attempt ceiling under-uses the one thing it actually has going for
	// it — sheer candidate count. A tighter per-attempt timeout (2s
	// instead of 3s) keeps the worst case from actually getting slower
	// while trying more candidates: 10×2s=20s worst case vs. the shared
	// 6×3s=18s, for roughly 65% better odds of finding a working server
	// instead of exhausting attempts and forcing the caller to fall back
	// to a whole different provider (which starts the process over).
	nordWGHandshakeTimeout   = 2 * time.Second
	nordWGMaxAcquireAttempts = 10

	// nordWGRetryUntilCtxDone: when true, acquireLease keeps cycling through
	// candidates past nordWGMaxAcquireAttempts instead of giving up — with
	// 8500+ servers, a bad run of 10 consecutive misses (observed live,
	// 2026-08-03: 10/10 failed with "no handshake within 2s" — looked like
	// either a genuinely bad stretch of the round-robin or the whole source
	// being unhealthy, e.g. Windows Firewall dropping inbound UDP replies
	// for a freshly-replaced binary) says nothing about the 8490 servers
	// never tried. Bounded by the caller's context instead of a fixed
	// count — a request that's already been abandoned (ctx cancelled/timed
	// out upstream) must still stop retrying, or a dead run would spin
	// forever burning VPS CPU for no one.
	nordWGRetryUntilCtxDone = true

	// nordWGMaxConcurrentConns: trần CỨNG cho TỔNG số kết nối WireGuard tồn
	// tại cùng lúc trên 1 tài khoản NordVPN — tính CẢ tunnel đang phục vụ
	// LẪN probe đang dò. NordVPN giới hạn ~10 kết nối đồng thời; vượt trần
	// thì server lặng lẽ không trả handshake, nhìn từ client giống hệt
	// "server hỏng", nên càng retry càng tệ.
	//
	// Cưỡng chế bằng semaphore (trường slots) chứ KHÔNG phải bằng cách đếm
	// map tunnel đang sống: cách đếm đó bỏ sót probe đang bay, nên nhiều
	// session cùng dò một lúc vẫn vượt trần dễ dàng — quan sát thật
	// (2026-08-04): 3 session cùng dò × 4 probe = 12 kết nối, và MỌI
	// handshake hỏng cho tới khi chúng thôi chồng lấn.
	//
	// Cần trần này vì SessionPool giữ nguyên lease của session đang rảnh
	// (idle-close chỉ đóng cửa sổ WebView2, không đổi IP — đúng yêu cầu
	// "chỉ đổi khi bị ban"), nên với 50 session, về lý thuyết có thể có tới
	// 50 tunnel mở cùng lúc. Chạm trần thì trả lỗi NGAY để MultiVPNProvider
	// chuyển sang nguồn khác (PIA/Surfshark/NordVPN-SOCKS5) thay vì để job
	// chết — xem MultiVPNProvider.acquireFrom.
	nordWGMaxConcurrentConns = 8

	// nordWGProbeFanOut: số ứng viên thử CÙNG LÚC mỗi vòng (xem acquireLease).
	// Số probe thực tế còn bị chặn thêm bởi số slot còn trống, nên giá trị
	// này là mức TRẦN mong muốn cho 1 vòng, không phải cam kết cứng.
	nordWGProbeFanOut = 4

	// nordWGFailCooldown: sau khi 1 server bắt tay hỏng, bỏ qua nó trong
	// khoảng này thay vì thử lại. Chỉ nhớ server HỎNG, cố tình KHÔNG nhớ
	// server tốt: bắt tay được lần này không đảm bảo lần sau (xem doc của
	// type — phụ thuộc số kết nối đồng thời của tài khoản tại thời điểm đó),
	// nên "danh sách server tốt" sẽ nhanh chóng sai và tệ hơn round-robin.
	//
	// TTL cố ý ngắn (10 phút) vì lỗi bắt tay KHÔNG chắc chắn là do server:
	// tài khoản chạm trần kết nối cũng làm mọi server im lặng y hệt. TTL dài
	// sẽ loại oan hàng loạt server tốt chỉ vì 1 sự cố phía mình.
	nordWGFailCooldown = 10 * time.Minute
)

// NordVPNWireGuardProvider hands out leases backed by real per-lease
// WireGuard tunnels to NordVPN's full server list (thousands of hosts,
// not just the ~12 dedicated SOCKS5 endpoints) — trading a heavier setup
// per lease (a real UDP handshake, not just a credential swap) for far
// more distinct exit IPs to rotate through over time.
//
// Empirically verified against the real API (2026-08-03): NordVPN's
// backend does not reliably keep more than one simultaneous WireGuard
// *data path* alive per account key — across several rounds of testing,
// most servers completed the handshake fine under concurrent load but
// silently stopped passing data for all but the most-recently-established
// session, with no error or teardown signal on the older ones. Exactly
// which servers behave differently isn't predictable from metadata
// (country, load, or whether they came from /v1/servers or the
// recommendations endpoint all produced a mix of hits and misses) — the
// only reliable signal is trying a real handshake AND a real HTTP round
// trip. So Acquire tries candidates one at a time (round-robin over the
// full list), verifying each for real before handing it out, and moves on
// immediately if one doesn't pan out rather than trying to remember which
// servers are "good" ahead of time.
//
// Each live tunnel exposes itself as a tiny local no-auth SOCKS5 server
// (see socks5_local_server.go) bound to 127.0.0.1 — the tunnel itself has
// no dialable network address (only a Go-level DialContext function from
// the userspace netstack), so this is what turns it into an ordinary
// socks5://127.0.0.1:<port> Lease.URL that LocalProxy's existing
// dialSOCKS5 path already knows how to use, unchanged.
//
// Built once at server startup and shared across every concurrent
// request, same reasoning as NordVPNProvider/PIAProvider — but unlike
// those, leases here ARE real per-caller resources (an open tunnel + a
// local listener), so Release/rotate must actually tear them down; kept
// in a map by Lease.Generation rather than workerID for the same reason
// those two providers avoid workerID: it repeats across concurrent
// requests once the provider is shared, so it can't be used as a key.
type NordVPNWireGuardProvider struct {
	privHex string

	mu      sync.Mutex
	servers []wgServer
	nextIdx int
	genCtr  int64
	live    map[int64]*wgTunnel
	// failedUntil: hostname → thời điểm được phép thử lại (xem
	// nordWGFailCooldown). Chỉ chứa server vừa hỏng, không phải server tốt.
	failedUntil map[string]time.Time

	// slots giới hạn TỔNG số kết nối WireGuard tồn tại cùng lúc trên tài
	// khoản — tính CẢ tunnel đang sống LẪN probe đang dò. Đây là điểm mấu
	// chốt: chỉ đếm tunnel sống là không đủ, vì nhiều session có thể cùng
	// dò một lúc (mỗi session bắn nordWGProbeFanOut probe), nên 3 session
	// dò song song đã là 12 kết nối — vượt trần ~10 của NordVPN và làm
	// TOÀN BỘ handshake im lặng hỏng, đúng triệu chứng quan sát được.
	slots chan struct{}

	refreshCancel context.CancelFunc
}

// NewNordVPNWireGuardProvider fetches the WireGuard private key and the
// current online server list once. Returns an error if either fails — a
// provider with no key or no servers can never build a working lease.
func NewNordVPNWireGuardProvider(token string) (*NordVPNWireGuardProvider, error) {
	privKeyB64, err := wgFetchPrivateKey(token)
	if err != nil {
		return nil, fmt.Errorf("nordvpn wireguard private key: %w", err)
	}
	privHex, err := wgKeyToHex(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("bad private key: %w", err)
	}
	p := &NordVPNWireGuardProvider{
		privHex:     privHex,
		live:        map[int64]*wgTunnel{},
		failedUntil: map[string]time.Time{},
		slots:       make(chan struct{}, nordWGMaxConcurrentConns),
	}
	if err := p.refreshServers(); err != nil {
		return nil, fmt.Errorf("nordvpn wireguard server list: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.refreshCancel = cancel
	go p.refreshLoop(ctx)

	return p, nil
}

// Close stops the background refresh loop and tears down every tunnel
// still open. Call once at server shutdown.
func (p *NordVPNWireGuardProvider) Close() {
	if p.refreshCancel != nil {
		p.refreshCancel()
	}
	p.mu.Lock()
	live := p.live
	p.live = map[int64]*wgTunnel{}
	p.mu.Unlock()
	for _, t := range live {
		t.socks.Close()
		t.dev.Close()
		<-p.slots
	}
}

func (p *NordVPNWireGuardProvider) refreshLoop(ctx context.Context) {
	t := time.NewTicker(wgServerRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.refreshServers(); err != nil {
				log.Printf("[NordVPN-WG] Warning: server list refresh failed: %v", err)
			}
		}
	}
}

func (p *NordVPNWireGuardProvider) refreshServers() error {
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Get("https://api.nordvpn.com/v1/servers?limit=0")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	var raw []struct {
		Hostname     string `json:"hostname"`
		Station      string `json:"station"`
		Load         int    `json:"load"`
		Status       string `json:"status"`
		Technologies []struct {
			Identifier string `json:"identifier"`
			Metadata   []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"metadata"`
		} `json:"technologies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	var servers []wgServer
	for _, s := range raw {
		if s.Status != "online" {
			continue
		}
		var pubKey string
		for _, t := range s.Technologies {
			if t.Identifier != "wireguard_udp" {
				continue
			}
			for _, m := range t.Metadata {
				if m.Name == "public_key" {
					pubKey = m.Value
				}
			}
		}
		if pubKey == "" {
			continue
		}
		pubHex, err := wgKeyToHex(pubKey)
		if err != nil {
			continue
		}
		servers = append(servers, wgServer{hostname: s.Hostname, station: s.Station, pubHex: pubHex, load: s.Load})
	}
	if len(servers) == 0 {
		return fmt.Errorf("no online wireguard_udp servers found")
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].load < servers[j].load })

	p.mu.Lock()
	p.servers = servers
	// Dọn các mục phạt đã hết hạn cùng lúc refresh danh sách — nếu không,
	// map này chỉ có thêm chứ không bao giờ bớt trong suốt đời server
	// (nextCandidate chỉ xoá mục nó tình cờ gặp lại).
	now := time.Now()
	for host, until := range p.failedUntil {
		if now.After(until) {
			delete(p.failedUntil, host)
		}
	}
	penalised := len(p.failedUntil)
	p.mu.Unlock()
	log.Printf("[NordVPN-WG] Loaded %d online WireGuard servers (%d đang bị tạm bỏ qua do lỗi gần đây)", len(servers), penalised)
	return nil
}

// nextCandidate returns the next server in the round-robin, bỏ qua những
// server vừa hỏng còn trong thời gian phạt (xem nordWGFailCooldown).
// Caller must hold p.mu.
//
// Quét tối đa 1 vòng danh sách: nếu MỌI server đều đang bị phạt (dấu hiệu
// sự cố diện rộng — thường là phía tài khoản mình, không phải server), thì
// trả về ứng viên kế tiếp như bình thường thay vì báo "hết server". Thà thử
// 1 server có thể hỏng còn hơn từ chối phục vụ hoàn toàn.
func (p *NordVPNWireGuardProvider) nextCandidate() (wgServer, error) {
	if len(p.servers) == 0 {
		return wgServer{}, fmt.Errorf("no NordVPN WireGuard servers loaded")
	}
	now := time.Now()
	for scanned := 0; scanned < len(p.servers); scanned++ {
		s := p.servers[p.nextIdx%len(p.servers)]
		p.nextIdx++
		until, penalised := p.failedUntil[s.hostname]
		if !penalised || now.After(until) {
			if penalised {
				delete(p.failedUntil, s.hostname)
			}
			return s, nil
		}
	}
	s := p.servers[p.nextIdx%len(p.servers)]
	p.nextIdx++
	return s, nil
}

// noteFailure ghi nhận 1 server vừa bắt tay hỏng để bỏ qua trong
// nordWGFailCooldown tới.
func (p *NordVPNWireGuardProvider) noteFailure(hostname string) {
	p.mu.Lock()
	p.failedUntil[hostname] = time.Now().Add(nordWGFailCooldown)
	p.mu.Unlock()
}

// tryOne attempts a full lease against one candidate: build the tunnel,
// wait briefly for a real handshake, then prove data actually flows with
// one real HTTP round trip. The handshake alone isn't proof enough — see
// the type doc for why a completed handshake can still be a dead end.
func (p *NordVPNWireGuardProvider) tryOne(s wgServer) (*wgTunnel, error) {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.5.0.2")},
		[]netip.Addr{netip.MustParseAddr("103.86.96.100")},
		1420,
	)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s:51820\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		p.privHex, s.pubHex, s.station,
	)
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, fmt.Errorf("ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device up: %w", err)
	}

	handshakeOK := false
	deadline := time.Now().Add(nordWGHandshakeTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		info, err := dev.IpcGet()
		if err == nil && strings.Contains(info, "last_handshake_time_sec=") && !strings.Contains(info, "last_handshake_time_sec=0\n") {
			handshakeOK = true
			break
		}
	}
	if !handshakeOK {
		dev.Close()
		return nil, fmt.Errorf("no handshake within %s", nordWGHandshakeTimeout)
	}

	client := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}, Timeout: wgProbeTimeout}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("data path check failed: %w", err)
	}
	resp.Body.Close()

	socksSrv, err := newLocalSOCKS5Server(func(network, addr string) (net.Conn, error) {
		return tnet.DialContext(context.Background(), network, addr)
	})
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("local socks5 listener: %w", err)
	}

	return &wgTunnel{dev: dev, socks: socksSrv}, nil
}

// acquireLease tìm 1 server dùng được, thử SONG SONG nhiều ứng viên mỗi
// vòng (nordWGProbeFanOut) và lấy cái bắt tay xong TRƯỚC TIÊN, các ứng
// viên còn lại bị đóng ngay khi xong.
//
// Lý do đổi từ tuần tự sang song song (2026-08-04, đo trên VPS thật): tỉ lệ
// 1 server bất kỳ dùng được khá thấp, nên thử lần lượt mỗi cái chờ tới 2s
// khiến việc lấy 1 kết nối mất 60-80s (quan sát thật: 30-40 lượt thử liên
// tiếp). Cùng tỉ lệ thành công đó, thử 6 cái cùng lúc cho kết quả trong
// ~2-4s, vì thời gian mỗi vòng bị chặn bởi 1 lần timeout chứ không phải
// cộng dồn. Đây thuần là chuyện chờ mạng (I/O), không phải tính toán, nên
// chạy song song gần như không tốn thêm CPU — đúng ràng buộc "không được
// chậm, ít tốn CPU".
//
// Vẫn KHÔNG nhớ "server nào tốt" — xem doc của type để biết vì sao điều đó
// không đáng tin ở NordVPN.
func (p *NordVPNWireGuardProvider) acquireLease(ctx context.Context, emit func(string)) (Lease, error) {
	// Không còn slot nào trống → trả lỗi ngay, KHÔNG chờ và KHÔNG retry:
	// mở thêm kết nối lúc này chắc chắn hỏng (xem nordWGMaxConcurrentConns),
	// và chờ ở đây chỉ làm job đứng im trong khi 3 nguồn VPN khác đang rảnh.
	// Trả lỗi để MultiVPNProvider chuyển nguồn là nhanh nhất cho người dùng.
	if len(p.slots) >= nordWGMaxConcurrentConns {
		return Lease{}, fmt.Errorf("đã đạt trần %d kết nối NordVPN WireGuard đồng thời", nordWGMaxConcurrentConns)
	}

	var lastErr error
	for attempt := 0; ; attempt += nordWGProbeFanOut {
		if attempt >= nordWGMaxAcquireAttempts {
			if !nordWGRetryUntilCtxDone {
				break
			}
			if err := ctx.Err(); err != nil {
				return Lease{}, fmt.Errorf("acquire cancelled after %d attempts: %w (last: %v)", attempt, err, lastErr)
			}
			// Past the normal ceiling and still going — let the caller know
			// this is taking a genuinely unusual number of tries rather than
			// silently retrying in the background with no visible signal.
			if attempt%(nordWGProbeFanOut*5) == 0 && emit != nil {
				emit(fmt.Sprintf("Vẫn đang tìm server NordVPN khả dụng (đã thử %d)…", attempt))
			}
		}

		t, err := p.probeRound(ctx)
		if err != nil {
			// Hết slot: KHÔNG thử lại ở đây. Vòng lặp này không có độ trễ
			// giữa các lần (mỗi vòng bình thường tự tốn ~2s vì chờ handshake),
			// nên quay lại ngay khi không dò được gì sẽ quay tít đốt CPU.
			// Trả lỗi để MultiVPNProvider chuyển sang nguồn VPN khác — nhanh
			// hơn cho người dùng và không lãng phí CPU của VPS.
			if errors.Is(err, errNordWGNoSlots) {
				return Lease{}, err
			}
			lastErr = err
			continue
		}
		p.mu.Lock()
		p.genCtr++
		gen := p.genCtr
		p.live[gen] = t
		p.mu.Unlock()
		return Lease{URL: "socks5://" + t.socks.Addr(), AcquiredAt: time.Now(), Generation: gen}, nil
	}
	return Lease{}, fmt.Errorf("no working NordVPN WireGuard server after %d attempts (last: %v)", nordWGMaxAcquireAttempts, lastErr)
}

// probeRound thử nordWGProbeFanOut ứng viên CÙNG LÚC và trả về tunnel đầu
// tiên dùng được. Mọi tunnel thắng-sau bị đóng ngay lập tức — bỏ sót 1 cái
// nghĩa là rò rỉ đúng kiểu đã làm hỏng cả nguồn NordVPN hôm nay (xem
// MultiVPNProvider.Release), nên hàm này luôn dọn hết phần thừa, kể cả khi
// tunnel về muộn sau khi đã có người thắng.
func (p *NordVPNWireGuardProvider) probeRound(ctx context.Context) (*wgTunnel, error) {
	type probeResult struct {
		tunnel *wgTunnel
		err    error
	}

	// Chỉ dò được bấy nhiêu ứng viên như số slot giành được — mỗi probe giữ
	// 1 slot suốt thời gian nó tồn tại (xem nordWGMaxConcurrentConns).
	// Giành slot không chặn: hết slot thì vòng này dò ít hơn, còn hơn là
	// đứng chờ trong khi vẫn còn nguồn VPN khác dùng được.
	acquired := 0
grab:
	for acquired < nordWGProbeFanOut {
		select {
		case p.slots <- struct{}{}:
			acquired++
		default:
			break grab // hết slot — dò với số ứng viên đang có
		}
	}
	if acquired == 0 {
		return nil, errNordWGNoSlots
	}

	candidates := make([]wgServer, 0, acquired)
	p.mu.Lock()
	for i := 0; i < acquired; i++ {
		s, err := p.nextCandidate()
		if err != nil {
			p.mu.Unlock()
			for j := 0; j < acquired; j++ {
				<-p.slots
			}
			return nil, err
		}
		candidates = append(candidates, s)
	}
	p.mu.Unlock()

	results := make(chan probeResult, len(candidates))
	for _, s := range candidates {
		go func(s wgServer) {
			t, err := p.tryOne(s)
			if err != nil {
				p.noteFailure(s.hostname)
				<-p.slots // probe hỏng → trả slot ngay
				results <- probeResult{err: fmt.Errorf("%s: %w", s.hostname, err)}
				return
			}
			// Probe thắng thì GIỮ nguyên slot (tunnel sống tiếp tục chiếm 1
			// kết nối); probe thua sẽ trả slot lúc bị đóng ở dưới.
			results <- probeResult{tunnel: t}
		}(s)
	}

	// Nhận kết quả đầu tiên thành công; phần còn lại vẫn phải nhận đủ để
	// đóng, nên việc dọn dẹp chạy nền chứ không chặn caller (mỗi probe đã tự
	// giới hạn bởi timeout handshake, không treo vô hạn).
	var (
		winner  *wgTunnel
		lastErr error
		got     int
	)
	for got = 0; got < len(candidates); got++ {
		r := <-results
		if r.err != nil {
			lastErr = r.err
			continue
		}
		winner = r.tunnel
		got++
		break
	}

	if remaining := len(candidates) - got; remaining > 0 {
		go func(n int) {
			for i := 0; i < n; i++ {
				r := <-results
				if r.tunnel != nil {
					// Probe thắng-sau: đóng tunnel VÀ trả slot nó đang giữ.
					// Bỏ sót bước trả slot ở đây sẽ làm số slot khả dụng rò rỉ
					// dần về 0 và khoá hẳn nguồn NordVPN-WG.
					r.tunnel.socks.Close()
					r.tunnel.dev.Close()
					<-p.slots
				}
			}
		}(remaining)
	}

	if winner == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("không ứng viên nào phản hồi")
		}
		return nil, lastErr
	}
	return winner, nil
}

func (p *NordVPNWireGuardProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	if emit != nil {
		emit("Đang tìm server NordVPN (WireGuard) khả dụng…")
	}
	return p.acquireLease(ctx, emit)
}

func (p *NordVPNWireGuardProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, emit func(string)) (Lease, error) {
	p.closeLease(oldLease.Generation)
	if emit != nil {
		emit("Đang đổi sang server NordVPN (WireGuard) khác…")
	}
	return p.acquireLease(ctx, emit)
}

// Release tears down the actual tunnel and local listener this lease
// owns — unlike NordVPNProvider/PIAProvider, a WireGuard lease is a real
// resource, not just a credential string, so there is something to clean
// up here.
func (p *NordVPNWireGuardProvider) Release(workerID int, lease Lease) {
	p.closeLease(lease.Generation)
}

func (p *NordVPNWireGuardProvider) closeLease(gen int64) {
	p.mu.Lock()
	t, ok := p.live[gen]
	if ok {
		delete(p.live, gen)
	}
	p.mu.Unlock()
	if ok {
		t.socks.Close()
		t.dev.Close()
		<-p.slots // trả lại slot kết nối tunnel này đang giữ
	}
}

func wgKeyToHex(b64Key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func wgFetchPrivateKey(token string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.nordvpn.com/v1/users/services/credentials", nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth("token", token)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	var c struct {
		NordlynxPrivateKey string `json:"nordlynx_private_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return "", err
	}
	if c.NordlynxPrivateKey == "" {
		return "", fmt.Errorf("empty nordlynx_private_key in response")
	}
	return c.NordlynxPrivateKey, nil
}
