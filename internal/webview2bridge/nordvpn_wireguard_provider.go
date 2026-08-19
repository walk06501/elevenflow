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
	// pubHex: which key's slot this tunnel is holding — needed so
	// closeLease/Close release into the SAME per-key channel it was
	// acquired from (see slotChanLocked).
	pubHex string
}

// errNordWGNoSlots: MỌI candidate quét được trong 1 lượt probeRound đều rơi
// vào key đã hết chỗ đồng thời (xem tryAcquireSlotLocked/capacityForKeyLocked)
// — lỗi "thử nguồn khác đi", KHÔNG phải "server này hỏng" — nên không được
// retry trong nội bộ provider.
//
// probeRound wrap sentinel này khi trả lỗi, để MultiVPNProvider.acquireFrom
// nhận ra và KHÔNG tính vào thống kê chất lượng (recordAttempt) — một lượt
// bị chặn vì hết slot chưa từng chạm tới 1 server thật nào, nên không nói
// lên được gì về việc "chọn server có tốt không". Trước khi có chỗ phân biệt
// này, mọi lần bị chặn hết slot bị tính y hệt 1 lần bắt tay thất bại thật,
// kéo tụt success_rate đo được của NordVPN-WG một cách sai lệch — nhìn giống
// hệt "chọn server tệ" trong khi thực ra là do trần kết nối đồng thời của
// đúng (các) key vừa được thử bị chạm (xem nordWGDefaultMaxConcurrentConns/
// nordWGPoolKeyCapacity).
var errNordWGNoSlots = errors.New("hết slot kết nối NordVPN WireGuard")

const (
	wgHandshakeTimeout      = 3 * time.Second
	wgProbeTimeout          = 3 * time.Second
	wgMaxAcquireAttempts    = 6
	wgServerRefreshInterval = 30 * time.Minute

	// nordWGHandshakeTimeout: a tighter per-attempt timeout (2s instead of
	// the shared 3s) than the other providers, on the reasoning that
	// NordVPN-WG's own pool (thousands of servers) is an order of magnitude
	// bigger than PIA's (hundreds) or Surfshark's (~140 fixed hosts), so
	// trying candidates faster matters more here.
	//
	// nordWGMaxAcquireAttempts: CORRECTED 2026-08-19 — this comment
	// previously argued FOR trying MORE candidates than the shared
	// wgMaxAcquireAttempts=6 (citing a since-changed value of 10), but the
	// constant below is 5, i.e. FEWER attempts than every other provider,
	// which argues the opposite of what this comment used to claim. Git
	// history: 735d92b introduced 10, 6fd800e ("Treat NordVPN WireGuard as
	// a single-connection source") dropped it to 5 without updating this
	// comment. Real worst case at 5 attempts is nordWGHandshakeTimeout (2s)
	// + wgProbeTimeout (3s) = 5s/attempt × 5 ≈ 25s, not the 20s this
	// comment used to claim (which also omitted the probe timeout). Left as
	// 5 for now since 6fd800e's actual motivation isn't reconstructable
	// from history alone — re-derive fresh from data before changing it
	// again, don't restore the old "try more" reasoning without new
	// evidence.
	nordWGHandshakeTimeout   = 2 * time.Second
	nordWGMaxAcquireAttempts = 5

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
	// Tắt (2026-08-04): thử mãi chỉ đúng khi lỗi là "server này xui, cái
	// khác sẽ được". Đo thật cho thấy KHÔNG phải vậy với NordVPN — trần 1
	// đường dữ liệu/khoá nghĩa là khi 1 session khác đang giữ tunnel Nord,
	// MỌI server đều hỏng như nhau, thử 8500 cái cũng vô ích (quan sát:
	// 60+ lượt liên tiếp). Bỏ cuộc sớm rồi để MultiVPNProvider chuyển sang
	// PIA/Surfshark/NordVPN-SOCKS5 nhanh hơn hẳn cho người dùng.
	nordWGRetryUntilCtxDone = false

	// nordWGDefaultMaxConcurrentConns: trần mặc định cho TỔNG số kết nối
	// WireGuard tồn tại cùng lúc trên 1 tài khoản NordVPN, cho MỌI public
	// key KHÔNG có mặt trong nordWGPoolKeyCapacity bên dưới — tính CẢ tunnel
	// đang phục vụ LẪN probe đang dò. Vượt trần thì server lặng lẽ không trả
	// handshake, nhìn từ client giống hệt "server hỏng", nên càng retry
	// càng tệ.
	//
	// Đặt 1 sau khi đo trên VPS thật (2026-08-04): với 1 server "dedicated"
	// thường, NordVPN chỉ giữ được ĐÚNG MỘT đường dữ liệu WireGuard trên 1
	// khoá tài khoản. Bằng chứng: tunnel vượt qua bài tự kiểm tra (handshake
	// + 1 GET thật) nhưng rồi WebView2 KHÔNG tải nổi trang, luôn timeout
	// 30s — vì tới lúc đó 1 tunnel khác vừa lập xong đã chiếm mất đường dữ
	// liệu; cùng lúc đó NordVPN-SOCKS5 tải trang trong ~2s.
	//
	// QUAN TRỌNG (2026-08-11, xem nordWGPoolKeyCapacity ngay dưới): kết luận
	// "1 kết nối" này chỉ đúng cho server "dedicated" thường — cmd/scanwgpools
	// đã đo thật và tìm ra 1 số ít backend "pool" (nhóm hostname dùng chung
	// 1 public key) chịu được NHIỀU kết nối đồng thời hơn hẳn. Trần này vẫn
	// là mặc định AN TOÀN cho phần còn lại (38/40 nhóm lớn nhất đo lại vẫn
	// đúng 0/10 ở lần scan 2026-08-11) — không hạ thấp barrier chứng minh
	// cho MỌI key, chỉ nới riêng cho những key đã có bằng chứng thật.
	nordWGDefaultMaxConcurrentConns = 1

	// nordWGProbeFanOut: số ứng viên thử CÙNG LÚC mỗi vòng (xem acquireLease).
	//
	// PHẢI là 1 với NordVPN. Dò song song là cách đúng cho PIA/Surfshark
	// (mỗi kết nối độc lập), nhưng với NordVPN thì các probe TỰ GIẾT NHAU:
	// mỗi handshake mới đá văng đường dữ liệu của probe trước, nên hầu hết
	// probe trượt bài kiểm tra và tỉ lệ thành công TỤT khi tăng số probe.
	// Đây là bài học ngược đời từ đo thật: fan-out 4 làm nguồn này tệ đi,
	// không phải nhanh lên.
	nordWGProbeFanOut = 1

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

// nordWGPoolKeyCapacity: WireGuard public keys (hex) confirmed by REAL
// concurrent-handshake testing (cmd/scanwgpools) to be "virtual server
// pool" backends that sustain far more than nordWGDefaultMaxConcurrentConns
// data paths per account at once — unlike an ordinary dedicated server's
// key, where the same test always gets 0/10.
//
// Public keys are backend identity, not account identity (see the type doc
// below: 224 keys shared across 8803+ hostnames) — a key proven here to
// support N concurrent connections supports N per ANY NordVPN account
// configured, old or new, not just the one the scan token belonged to.
//
// Capacity is set to the highest count ACTUALLY OBSERVED, never
// extrapolated upward — cmd/scanwgpools's -per-group only went to 10, so
// these numbers are a proven FLOOR on real capacity, not necessarily the
// ceiling. Re-run with a higher -per-group against a key already listed
// here to find out if it goes higher before raising its number.
//
// Re-verify periodically (server pools are NordVPN's own infrastructure
// choice, not contractually stable) — last confirmed 2026-08-11 against
// the 40 largest key groups (min 6 hosts each); only these 2 cleared the
// >=5/10 bar out of 40 tested:
//
//	go run ./cmd/scanwgpools -token <ELEVEN_NORDVPN_TOKEN> -min-hosts 6 -max-groups 40 -per-group 10
var nordWGPoolKeyCapacity = map[string]int{
	// uk1784.nordvpn.com's backend, 828 hosts sharing this key — 10/10
	// concurrent handshakes succeeded (perfect score, likely higher than 10
	// in reality — untested past the scan's batch size).
	"2b9de5db03881d4df6eb6b17e4dff9900bc2bede2be7994dba2df411bbda0e51": 10,
	// au569.nordvpn.com's backend, 61 hosts — 5/10, borderline: real but
	// weaker than the uk1784 pool, kept conservative rather than rounded up.
	"7fec68f613a3544907564189a30b91194e541044970a9888df06024193d28a5b": 5,
}

// nordWGSlotChanBuffer: fixed buffer size for EVERY key's slot channel,
// regardless of that key's actual trusted capacity. A Go channel's buffer
// can't grow after creation, but a key's trusted capacity CAN grow after
// its channel already exists — nordvpn_wireguard_discovery.go promotes a
// key from the default the first time it's seen to a proven number well
// after slotChanLocked may have already created a 1-slot channel for it
// (e.g. it briefly appeared as a round-robin fallback candidate before
// discovery ever tested it). Sizing every channel to this one constant up
// front sidesteps that instead of tracking "was this channel created before
// or after promotion" — it's just a physical upper bound, not the
// enforcement itself: tryAcquireSlotLocked's len(ch) check against
// capacityForKeyLocked() is what actually holds an ordinary/degraded key to
// nordWGDefaultMaxConcurrentConns regardless of how much spare buffer it
// sits in. Matches nordWGDiscoveryPerGroup, the highest concurrency this
// codebase ever tests for — proven capacity, hand-curated or discovered,
// can never legitimately exceed it.
const nordWGSlotChanBuffer = nordWGDiscoveryPerGroup

// capacityForKeyLocked returns how many concurrent connections this key is
// CURRENTLY trusted for: the scanwgpools-proven ceiling (nordWGPoolKeyCapacity)
// unless live traffic through this very process disagrees. If the key has
// racked up enough real attempts (same bar as rankedGoodKeysLocked) and its
// live success rate has fallen below "good", something changed since the
// scan (NordVPN resized/retired the pool, etc.) — continuing to trust the
// old number would just manufacture more failures, so it's treated as an
// ordinary key until a fresh cmd/scanwgpools run re-proves it. This is what
// makes the hardcoded table safe to leave stale for a while: it can only
// ever get MORE conservative on its own, never silently keep trusting a
// number reality has stopped matching. Caller must hold p.mu.
func (p *NordVPNWireGuardProvider) capacityForKeyLocked(pubHex string) int {
	proven, isPool := nordWGPoolKeyCapacity[pubHex]
	if !isPool {
		// Not in the hand-curated table — check whether discoveryLoop found
		// this one on its own (nordvpn_wireguard_discovery.go). Same
		// live-degrade protection applies below either way, so a
		// discovered key is trusted exactly as much as a hand-curated one,
		// never more.
		discovered, ok := p.discoveredPoolCapacity[pubHex]
		if !ok {
			return nordWGDefaultMaxConcurrentConns
		}
		proven = discovered
	}
	const minAttempts = 5
	const minSuccessRate = 0.7
	// Degrade check reads BOTH keyStats (real traffic) and discoveryStats
	// (probe results) combined — unlike rankedGoodKeysLocked's promotion
	// path, which deliberately reads keyStats only (see noteKeyResult's doc
	// comment for why the two need different evidence). Demoting a
	// capacity claim is reasonable evidence from either source: if
	// discovery itself re-tested this key and it failed to hold capacity,
	// that's just as informative as real traffic failing the same way.
	attempts, successes := 0, 0
	if st, ok := p.keyStats[pubHex]; ok {
		attempts += st.attempts
		successes += st.successes
	}
	if st, ok := p.discoveryStats[pubHex]; ok {
		attempts += st.attempts
		successes += st.successes
	}
	if attempts >= minAttempts {
		if rate := float64(successes) / float64(attempts); rate < minSuccessRate {
			return nordWGDefaultMaxConcurrentConns
		}
	}
	return proven
}

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
// immediately if one doesn't pan out.
//
// CORRECTED 2026-08-19: this paragraph used to end "...rather than trying
// to remember which servers are 'good' ahead of time" — that stopped being
// true when nextCandidate started consulting rankedGoodKeysLocked (a
// persistent-for-the-process memory of keys with enough proven attempts and
// success rate), which takes priority over plain round-robin. What's still
// accurate: no server is EVER assumed good without having actually been
// tried — the memory is earned from real attempts, not inferred from
// metadata.
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
// keyStat: số lần thử/thành công tích luỹ thật cho 1 public key (1 backend
// thật — xem doc comment ở đầu file: 8803 server chỉ có 224 public key
// khác nhau, và cùng key nghĩa là cùng backend). Học dần từ traffic thật
// trong suốt vòng đời tiến trình, KHÔNG lưu đĩa — quán tính trong 1 lần
// chạy dài là đủ để tự ưu tiên đúng nhóm tốt, không cần bền qua restart.
type keyStat struct {
	attempts  int
	successes int
}

type NordVPNWireGuardProvider struct {
	privHex string
	// label: which account this instance belongs to (e.g. "NordVPN #1"),
	// from the portal's eleven_vpn_accounts.label — folded into Name() so
	// MultiVPNProvider.Stats()/statsLogger key each account separately.
	// Added 2026-08-19: with 2+ accounts each building their own provider
	// instance (main.go's per-account loop), Name() previously returned
	// the same constant "NordVPN-WG" for both, so MultiVPNProvider.stats
	// (keyed by Name()) silently summed both accounts into one bucket — a
	// dead account would just look like the live one's rate had halved,
	// and there was no way to tell "1 attempt landed on account A, next on
	// account B" from "2 attempts both landed on the same account", which
	// is exactly the distinction needed to test the 1-data-path-per-account
	// contention theory against real production traffic.
	label string

	mu      sync.Mutex
	servers []wgServer
	// byKey: public key → toàn bộ hostname mang key đó (xem tryOne/probeRound).
	// Dựng lại mỗi lần refreshServers() chạy, cùng lúc với `servers`.
	byKey   map[string][]wgServer
	nextIdx int
	genCtr  int64
	live    map[int64]*wgTunnel
	// failedUntil: hostname → thời điểm được phép thử lại (xem
	// nordWGFailCooldown). Chỉ chứa server vừa hỏng, không phải server tốt.
	failedUntil map[string]time.Time
	// keyStats: public key → thống kê thật đã tích luỹ (xem keyStat).
	keyStats map[string]*keyStat
	// keyHostIdx: public key → con trỏ xoay vòng trong byKey[key] (xem
	// nextCandidate's ranked-key loop) — để các lần gọi liên tiếp trải đều
	// ra nhiều hostname khác nhau của cùng 1 key thay vì luôn trả về đúng
	// hostname đầu tiên.
	keyHostIdx map[string]int

	// discoveredPoolCapacity: public key → trần đồng thời tự phát hiện được
	// LÚC CHẠY (xem nordvpn_wireguard_discovery.go), song song với bảng tay
	// nordWGPoolKeyCapacity chứ không thay thế — quét thủ công 1 lần
	// (cmd/scanwgpools) chỉ bắt được ảnh chụp tại thời điểm chạy, không tự
	// phát hiện pool MỚI NordVPN thêm sau này; discoveryLoop lấp đúng chỗ
	// đó, chạy nền suốt vòng đời tiến trình.
	//
	// Lưu đĩa cùng discoveryStats từ 2026-08-19 (nordWGDiscoveryPath) —
	// SỬA LẠI quyết định ban đầu (từng cố tình không lưu, lý do cũ: "quán
	// tính 1 lần chạy dài là đủ"). Lý do đổi: restart xoá sạch tiến độ dò
	// (~224 nhóm key, ~1 nhóm/20 phút — vài ngày mới quét hết), và VPS này
	// restart đủ thường xuyên (2 lần trong 1 ngày, chính phiên hôm nay) để
	// việc đó thành lãng phí thật. QUAN TRỌNG: lưu SỐ capacity mà không lưu
	// BẰNG CHỨNG (discoveryStats) từng là 1 lỗi thật đã xảy ra (fix trong
	// cùng ngày) — capacityForKeyLocked's cam kết "chỉ có thể trở nên thận
	// trọng hơn theo thời gian, không bao giờ âm thầm tin lại số liệu đã
	// lỗi thời" chỉ đúng nếu số liệu VÀ bằng chứng cùng sống hoặc cùng chết
	// qua restart — không thể lưu cái này mà bỏ cái kia.
	discoveredPoolCapacity map[string]int
	// discoveryStats: public key → thống kê THẬT từ discovery probe (KHÁC
	// keyStats — xem noteDiscoveryResult's doc comment để biết vì sao 2 map
	// này phải tách nhau: discovery cố tình test ở mức đồng thời cao,
	// keyStats chỉ nên phản ánh traffic thật). Lưu đĩa cùng
	// discoveredPoolCapacity (cùng file, cùng lúc) — đây chính là "bằng
	// chứng" mà capacityForKeyLocked cần để biết 1 capacity đã lưu còn đáng
	// tin hay không sau restart.
	discoveryStats map[string]*keyStat
	// discoveryCursor: con trỏ xoay vòng qua các nhóm key chưa được phân
	// loại (xem nextDiscoveryCandidateLocked), để discoveryLoop rải đều việc
	// dò qua nhiều lần chạy thay vì cứ thử đi thử lại đúng 1 nhóm.
	discoveryCursor int

	// slotsByKey giới hạn số kết nối WireGuard tồn tại cùng lúc trên tài
	// khoản — tính CẢ tunnel đang sống LẪN probe đang dò — nhưng giờ tách
	// RIÊNG theo từng public key thay vì 1 trần chung cho cả tài khoản (xem
	// nordWGPoolKeyCapacity/capacityForKeyLocked): 1 key "pool" đã chứng
	// minh chịu được nhiều kết nối không nên bị trần của key "dedicated"
	// thường (1) kéo xuống, và ngược lại — 1 key thường tràn slot không được
	// phép mượn "chỗ" của key pool khác. Tạo lười (lazy) theo từng key gặp
	// lần đầu, xem slotChanLocked. Vẫn cùng lý do cần đếm cả probe đang bay
	// chứ không chỉ tunnel đã sống: nhiều session dò cùng 1 key một lúc vẫn
	// phải cộng dồn đúng, nếu không sẽ lặp lại đúng triệu chứng đã thấy
	// 2026-08-04 (nhiều probe chồng lấn phá lẫn nhau).
	slotsByKey map[string]chan struct{}

	refreshCancel context.CancelFunc
}

// slotChanLocked returns the channel backing one public key's slots,
// creating it (buffer fixed at nordWGSlotChanBuffer) the first time this
// key is seen. Caller must hold p.mu. Only for release/lookup — acquiring a
// slot goes through tryAcquireSlotLocked instead, which additionally
// enforces the possibly-lower CURRENT trust level (capacityForKeyLocked) on
// top of this fixed buffer.
func (p *NordVPNWireGuardProvider) slotChanLocked(pubHex string) chan struct{} {
	if ch, ok := p.slotsByKey[pubHex]; ok {
		return ch
	}
	ch := make(chan struct{}, nordWGSlotChanBuffer)
	p.slotsByKey[pubHex] = ch
	return ch
}

// tryAcquireSlotLocked attempts to claim 1 concurrent-connection slot for
// pubHex, gated by the CURRENT trusted capacity (capacityForKeyLocked) —
// which can be lower than the channel's static buffer size if live traffic
// has shown this key degrading (see that function's doc). Non-blocking:
// returns ok=false immediately if at capacity, never waits. Caller must
// hold p.mu; the returned channel (when ok) is what the caller must later
// receive from to release the slot.
func (p *NordVPNWireGuardProvider) tryAcquireSlotLocked(pubHex string) (chan struct{}, bool) {
	ch := p.slotChanLocked(pubHex)
	if len(ch) >= p.capacityForKeyLocked(pubHex) {
		return nil, false
	}
	select {
	case ch <- struct{}{}:
		return ch, true
	default:
		// Buffer momentarily full even though our trusted cap said there was
		// room — a race with another goroutine between the len() check and
		// this send. Vanishingly rare and harmless: caller just treats it as
		// "no room right now", same as the len() check failing outright.
		return nil, false
	}
}

// NewNordVPNWireGuardProvider fetches the WireGuard private key and the
// current online server list once. Returns an error if either fails — a
// provider with no key or no servers can never build a working lease.
// label identifies which account this instance is (see the struct field's
// doc comment) — pass "" if unknown (Name() falls back to the bare source
// name, matching pre-2026-08-19 behavior).
func NewNordVPNWireGuardProvider(token string, label string) (*NordVPNWireGuardProvider, error) {
	privKeyB64, err := wgFetchPrivateKey(token)
	if err != nil {
		return nil, fmt.Errorf("nordvpn wireguard private key: %w", err)
	}
	privHex, err := wgKeyToHex(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("bad private key: %w", err)
	}
	p := &NordVPNWireGuardProvider{
		privHex:                privHex,
		label:                  label,
		live:                   map[int64]*wgTunnel{},
		failedUntil:            map[string]time.Time{},
		keyStats:               map[string]*keyStat{},
		discoveryStats:         map[string]*keyStat{},
		keyHostIdx:             map[string]int{},
		discoveredPoolCapacity: map[string]int{},
		slotsByKey:             map[string]chan struct{}{},
	}
	if err := p.refreshServers(); err != nil {
		return nil, fmt.Errorf("nordvpn wireguard server list: %w", err)
	}

	if capacity, stats, err := loadNordWGDiscovered(privHex); err != nil {
		log.Printf("[NordVPN-WG] Warning: failed to load discovered pool cache: %v", err)
	} else if len(capacity) > 0 {
		p.discoveredPoolCapacity = capacity
		p.discoveryStats = stats
		log.Printf("[NordVPN-WG] Loaded %d previously-discovered pool key(s) from cache", len(capacity))
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.refreshCancel = cancel
	go p.refreshLoop(ctx)
	go p.discoveryLoop(ctx)

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
		p.mu.Lock()
		slotCh := p.slotChanLocked(t.pubHex)
		p.mu.Unlock()
		<-slotCh
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
		// Double VPN / Onion Over VPN (2-hop groups, ~149/8803 servers,
		// ~1.7%) were considered for exclusion here on the strength of
		// ProtonVPN's Secure Core finding (2026-08-05: confirmed via real
		// rx/tx byte counts that a 2-hop server's tunnel was healthy, just
		// slower than a shared timeout tuned for single-hop). Deliberately
		// NOT excluded: unlike Proton, this provider's dominant failure
		// mode is the account-level connection cap (see file doc comment),
		// not per-server latency, so there is no actual evidence these
		// specific groups behave differently here — and rankedGoodKeysLocked
		// already down-weights whatever performs badly from real traffic,
		// so a hard categorical exclusion would only cost IP diversity
		// (which main.go's weight comment explicitly values) for an
		// unproven benefit.
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

	byKey := map[string][]wgServer{}
	for _, s := range servers {
		byKey[s.pubHex] = append(byKey[s.pubHex], s)
	}

	p.mu.Lock()
	p.servers = servers
	p.byKey = byKey
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

// rankedGoodKeysLocked trả về MỌI public key đã đủ dữ liệu và đạt ngưỡng
// đáng tin (>=5 lần thử, >=70% thành công), xếp từ tỉ lệ thành công cao
// xuống thấp — không chỉ 1 key tốt nhất. Lý do: thực tế đo được không chỉ
// có 1 key tốt (scan tay tìm ra ~10 key khác nhau, lớn nhỏ khác nhau), nên
// nếu chỉ nhớ đúng 1 key, lúc key đó đang bị phạt tạm thời sẽ lãng phí toàn
// bộ key tốt còn lại và rơi thẳng về ngẫu nhiên trên cả 8803 server. Ngưỡng
// cố tình khắt khe để vài lần may mắn đầu tiên không đủ đẩy 1 key tầm
// thường lên — key nào chưa đủ dữ liệu thì KHÔNG bị phạt gì cả, chỉ đơn
// giản là rơi xuống round-robin bình thường bên dưới (chính là cách thăm
// dò/khám phá key mới diễn ra một cách tự nhiên).
// Caller must hold p.mu.
func (p *NordVPNWireGuardProvider) rankedGoodKeysLocked() []string {
	const minAttempts = 5
	const minSuccessRate = 0.7
	type scored struct {
		key  string
		rate float64
	}
	var good []scored
	for key, st := range p.keyStats {
		if st.attempts < minAttempts {
			continue
		}
		rate := float64(st.successes) / float64(st.attempts)
		if rate >= minSuccessRate {
			// Sort key is the Wilson lower bound, not the raw rate — see
			// rank_confidence.go. Eligibility (the >= minSuccessRate gate
			// above) still uses the raw rate, unchanged.
			good = append(good, scored{key, wilsonLowerBound(st.successes, st.attempts)})
		}
	}
	sort.Slice(good, func(i, j int) bool { return good[i].rate > good[j].rate })
	out := make([]string, len(good))
	for i, g := range good {
		out[i] = g.key
	}
	return out
}

// nextCandidate returns the next server in the round-robin, bỏ qua những
// server vừa hỏng còn trong thời gian phạt (xem nordWGFailCooldown) VÀ
// những public key đã biết hết chỗ đồng thời trong lượt probeRound này
// (skipKeys — xem doc comment tham số).
// Caller must hold p.mu.
//
// Trước tiên thử lần lượt các public key đã chứng minh đáng tin qua traffic
// thật (rankedGoodKeysLocked, xếp tốt dần), mỗi key thử hostname còn dùng
// được (chưa bị phạt) của nó — không chỉ đúng 1 key tốt nhất, vì thực tế đo
// được có nhiều key tốt cùng lúc (xem doc comment của rankedGoodKeysLocked).
// Chỉ khi TOÀN BỘ key tốt đều không còn hostname dùng được (mọi key tốt
// cùng lúc bị phạt hết — hiếm) mới rơi xuống round-robin thường như cũ.
//
// skipKeys: các public key mà probeRound VỪA xác nhận hết chỗ đồng thời
// (tryAcquireSlotLocked trả false) trong CHÍNH lượt gọi này — bắt buộc phải
// có tham số này kể từ khi trần chuyển sang theo từng key (2026-08-11):
// hết chỗ đồng thời KHÔNG đưa hostname vào failedUntil (đó chỉ dành cho bắt
// tay thất bại thật), nên nếu không có skipKeys, 1 key pool lớn (vd 828
// host) đang bị chiếm hết chỗ sẽ khiến hàm này cứ trả về hostname CỦA CHÍNH
// KEY ĐÓ mãi (xoay qua keyHostIdx, luôn có hostname "chưa bị phạt" vì hết
// chỗ khác hẳn bị phạt) — không bao giờ rơi xuống key tốt kế tiếp hay
// round-robin, dù ở đó thật sự còn chỗ trống.
//
// Quét tối đa 1 vòng danh sách: nếu MỌI server đều đang bị phạt hoặc thuộc
// key trong skipKeys (dấu hiệu sự cố diện rộng — thường là phía tài khoản
// mình, không phải server), thì trả về ứng viên kế tiếp như bình thường
// thay vì báo "hết server". Thà thử 1 server có thể hỏng còn hơn từ chối
// phục vụ hoàn toàn.
func (p *NordVPNWireGuardProvider) nextCandidate(skipKeys map[string]bool) (wgServer, error) {
	if len(p.servers) == 0 {
		return wgServer{}, fmt.Errorf("no NordVPN WireGuard servers loaded")
	}
	now := time.Now()

	for _, key := range p.rankedGoodKeysLocked() {
		if skipKeys[key] {
			continue
		}
		hosts := p.byKey[key]
		if len(hosts) == 0 {
			continue
		}
		// Rotate through this key's OWN hostnames (keyHostIdx) instead of
		// always starting from hosts[0] — used to not matter (every
		// hostname of a key is the same 1-connection backend), but matters
		// now that a proven "pool" key (nordWGPoolKeyCapacity) can serve
		// several REAL concurrent connections: cmd/scanwgpools proved that
		// against several DIFFERENT hostnames of the same key tested at
		// once, not the same one repeated, so repeated calls here (e.g.
		// probeRound filling more than one slot) need to actually spread
		// out to get that concurrency in practice instead of only ever
		// offering hosts[0] again the instant it's back out of cooldown.
		start := p.keyHostIdx[key]
		for i := 0; i < len(hosts); i++ {
			s := hosts[(start+i)%len(hosts)]
			until, penalised := p.failedUntil[s.hostname]
			if !penalised || now.After(until) {
				if penalised {
					delete(p.failedUntil, s.hostname)
				}
				p.keyHostIdx[key] = (start + i + 1) % len(hosts)
				return s, nil
			}
		}
		// Mọi hostname của key này đang bị phạt hết — thử key tốt kế tiếp
		// thay vì rơi thẳng xuống round-robin ngay.
	}

	for scanned := 0; scanned < len(p.servers); scanned++ {
		s := p.servers[p.nextIdx%len(p.servers)]
		p.nextIdx++
		if skipKeys[s.pubHex] {
			continue
		}
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

// noteKeyResult tích luỹ 1 kết quả THẬT (từ 1 lease phục vụ traffic thật,
// gọi trong probeRound) vào thống kê của public key đó — đây là dữ liệu
// rankedGoodKeysLocked dùng để quyết định key nào đáng ưu tiên (tên hàm cũ
// trong comment, bestKeyLocked, đã đổi thành rankedGoodKeysLocked từ lâu).
// Chỉ cộng dồn trong bộ nhớ suốt vòng đời tiến trình, cố tình KHÔNG lưu đĩa
// (xem doc comment của keyStat).
//
// Discovery ticks (nordvpn_wireguard_discovery.go's runDiscoveryTick) do
// NOT call this — see noteDiscoveryResult below. Trước 2026-08-19 cả 2
// nguồn cùng ghi vào chung map này, và discovery cố tình test ở mức đồng
// thời 10 (nordWGDiscoveryPerGroup) trong khi 1 key thường chỉ chịu được 1
// kết nối (nordWGDefaultMaxConcurrentConns) — nghĩa là MỌI lượt discovery
// trên 1 key thường tự ghi ra ~9 lỗi/10, cần 22+ lần thành công thật LIÊN
// TIẾP mới gỡ được, rồi bị "đầu độc" lại ở lượt discovery kế tiếp (key
// thường không có cơ chế "đã xác nhận bình thường, thôi test" — xem
// nextDiscoveryCandidateLocked). Hậu quả: rankedGoodKeysLocked trên thực tế
// chỉ có thể chứa 2 key đã hard-code sẵn (chúng được loại trừ khỏi
// discovery), traffic thật không bao giờ tự "học" thêm được key mới nào.
func (p *NordVPNWireGuardProvider) noteKeyResult(pubHex string, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, exists := p.keyStats[pubHex]
	if !exists {
		st = &keyStat{}
		p.keyStats[pubHex] = st
	}
	st.attempts++
	if ok {
		st.successes++
	}
}

// noteDiscoveryResult tích luỹ 1 kết quả từ discovery probe (không phải
// traffic thật) vào discoveryStats — map RIÊNG, tách khỏi keyStats để
// discovery's tự-thiết-kế "test ở mức đồng thời 10" không đầu độc thống kê
// quyết định key nào vào rankedGoodKeysLocked (xem noteKeyResult's doc
// comment). capacityForKeyLocked vẫn đọc CẢ 2 map — degrade check của nó
// (hạ trust nếu traffic thật/discovery cho thấy key không còn chịu nổi
// capacity đã biết) hợp lý ở cả 2 nguồn, chỉ có promotion (rankedGoodKeysLocked)
// mới cần tách riêng.
func (p *NordVPNWireGuardProvider) noteDiscoveryResult(pubHex string, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, exists := p.discoveryStats[pubHex]
	if !exists {
		st = &keyStat{}
		p.discoveryStats[pubHex] = st
	}
	st.attempts++
	if ok {
		st.successes++
	}
}

// tryOne attempts a full lease against one candidate: build the tunnel,
// wait briefly for a real handshake, then prove data actually flows with
// one real HTTP round trip. The handshake alone isn't proof enough — see
// the type doc for why a completed handshake can still be a dead end.
func (p *NordVPNWireGuardProvider) tryOne(s wgServer) (*wgTunnel, error) {
	// MTU 1420 (WireGuard's generic default) → 1280, and a second DNS
	// server, 2026-08-19: cross-checked against several public NordVPN
	// WireGuard client implementations on GitHub. tis24dev/NordVPN-Easy-
	// OpenWrt (has real CI) documents that the official NordVPN app itself
	// pins NordLynx's MTU to 1280 specifically to avoid "PMTUD blackholes"
	// on paths with extra encapsulation (PPPoE/IPv6/double-NAT) — routers
	// silently drop oversized packets instead of returning the ICMP
	// "fragmentation needed" that would let the OS negotiate down. Since
	// this provider is a raw netstack.CreateNetTUN with no OS-level PMTUD,
	// a too-high MTU here fails exactly the way this file's own doc
	// comment already describes: handshake completes and a small HTTP GET
	// succeeds (fits under any MTU), but WebView2's real page loads
	// (larger TLS/JS payloads) hang — previously attributed entirely to
	// the "1 data path per account" limit, but the two symptoms are not
	// mutually exclusive and this one is cheap to rule out. DNS pair
	// 103.86.96.100/103.86.99.100 confirmed by two independent repos
	// (wgnord and NordVPN-Easy-OpenWrt) as NordVPN's own resolvers.
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.5.0.2")},
		[]netip.Addr{netip.MustParseAddr("103.86.96.100"), netip.MustParseAddr("103.86.99.100")},
		1280,
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

// acquireLease tìm 1 server dùng được qua probeRound.
//
// CORRECTED 2026-08-19 — 2 đoạn dưới đây đã SAI so với code hiện tại, giữ
// lại nguyên văn kèm đính chính thay vì xoá, vì lý do lịch sử vẫn hữu ích:
//
//  1. "Thử SONG SONG nhiều ứng viên mỗi vòng" — ĐÚNG khi viết (2026-08-04,
//     nordWGProbeFanOut=4 lúc đó), nhưng SAI từ 6fd800e ("Treat NordVPN
//     WireGuard as a single-connection source"): nordWGProbeFanOut đã đổi
//     về 1 (xem const doc — probe song song tự giết nhau trên NordVPn,
//     đo được kết quả TỆ hơn khi tăng fan-out, ngược hẳn lý do đổi sang
//     song song lúc đầu). acquireLease/probeRound hiện chạy TUẦN TỰ từng
//     ứng viên 1. Đừng bật song song lại cho Nord nếu không có bằng chứng
//     mới — đã thử, đã đo, đã revert.
//  2. "Vẫn KHÔNG nhớ 'server nào tốt'" — cũng sai, xem đính chính ở doc
//     comment của type (nextCandidate ưu tiên rankedGoodKeysLocked).
func (p *NordVPNWireGuardProvider) acquireLease(ctx context.Context, emit func(string)) (Lease, error) {
	// The old upfront "any slot free at all?" fast-fail is gone: capacity is
	// per-key now (see nordWGPoolKeyCapacity), so "no room" can only be
	// answered per-candidate, not for the account as a whole before even
	// picking one — that check now lives inside probeRound/nextCandidate.

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
// tiên dùng được. nordWGProbeFanOut = 1 hiện tại (xem const doc — song song
// tự giết nhau trên Nord), nên trên thực tế đây là tuần tự từng ứng viên 1;
// máy móc goroutine/channel dưới đây vẫn giữ nguyên để dễ bật lại fan-out >
// 1 nếu sau này có bằng chứng ngược lại, không phải vì đang chạy song song
// thật. Mọi tunnel thắng-sau bị đóng ngay lập tức — bỏ sót 1 cái
// nghĩa là rò rỉ đúng kiểu đã làm hỏng cả nguồn NordVPN hôm nay (xem
// MultiVPNProvider.Release), nên hàm này luôn dọn hết phần thừa, kể cả khi
// tunnel về muộn sau khi đã có người thắng.
//
// Khác bản cũ (trước 2026-08-11): trước đây giành TRƯỚC nordWGProbeFanOut
// "chỗ" từ 1 trần chung cho cả tài khoản, RỒI mới chọn candidate — không
// còn hợp lý khi mỗi public key có trần riêng (xem nordWGPoolKeyCapacity),
// vì lúc giành chỗ chưa biết candidate sẽ rơi vào key nào. Giờ chọn
// candidate TRƯỚC (nextCandidate, đã ưu tiên key tốt + xoay vòng hostname
// trong key đó), rồi xin đúng 1 chỗ trong slot RIÊNG của key đó
// (tryAcquireSlotLocked); nếu key đó vừa hết chỗ, thử candidate kế tiếp
// (nextCandidate tự xoay sang hostname/key khác) — quét tối đa 1 lượt toàn
// bộ server để không xoay vòng vô hạn khi tài khoản thật sự hết chỗ ở mọi
// nơi.
func (p *NordVPNWireGuardProvider) probeRound(ctx context.Context) (*wgTunnel, error) {
	type picked struct {
		s    wgServer
		slot chan struct{}
	}

	var candidates []picked
	// skipKeys: key nào vừa xác nhận hết chỗ trong CHÍNH lượt này thì không
	// hỏi lại nextCandidate() nữa — bắt buộc phải có, xem nextCandidate's
	// doc comment về vì sao thiếu nó sẽ làm hàm này quét cả len(p.servers)
	// vô ích mỗi khi đúng key tốt nhất (thường là 1 pool lớn) đang bị chiếm
	// hết chỗ, thay vì rơi xuống key/server khác thật sự còn trống ngay.
	skipKeys := map[string]bool{}
	p.mu.Lock()
	if len(p.servers) == 0 {
		p.mu.Unlock()
		return nil, fmt.Errorf("no NordVPN WireGuard servers loaded")
	}
	for scanned := 0; len(candidates) < nordWGProbeFanOut && scanned < len(p.servers); scanned++ {
		s, err := p.nextCandidate(skipKeys)
		if err != nil {
			break
		}
		slot, ok := p.tryAcquireSlotLocked(s.pubHex)
		if !ok {
			skipKeys[s.pubHex] = true // key này hết chỗ — đừng hỏi lại nữa trong lượt này
			continue
		}
		candidates = append(candidates, picked{s: s, slot: slot})
	}
	p.mu.Unlock()

	if len(candidates) == 0 {
		return nil, errNordWGNoSlots
	}

	type probeResult struct {
		tunnel *wgTunnel
		slot   chan struct{}
		err    error
	}
	results := make(chan probeResult, len(candidates))
	for _, c := range candidates {
		go func(c picked) {
			t, err := p.tryOne(c.s)
			if err != nil {
				p.noteFailure(c.s.hostname)
				p.noteKeyResult(c.s.pubHex, false)
				<-c.slot // probe hỏng → trả slot ngay
				results <- probeResult{err: fmt.Errorf("%s: %w", c.s.hostname, err)}
				return
			}
			p.noteKeyResult(c.s.pubHex, true)
			t.pubHex = c.s.pubHex
			// Probe thắng thì GIỮ nguyên slot (tunnel sống tiếp tục chiếm 1
			// kết nối); probe thua sẽ trả slot lúc bị đóng ở dưới.
			results <- probeResult{tunnel: t, slot: c.slot}
		}(c)
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
					// dần về 0 và khoá hẳn key đó.
					r.tunnel.socks.Close()
					r.tunnel.dev.Close()
					<-r.slot
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

// Name identifies this source in MultiVPNProvider's per-provider stats
// (see multi_vpn_provider.go). Includes the account label (2026-08-19) so
// stats no longer sum multiple accounts into one bucket — see the label
// field's doc comment.
func (p *NordVPNWireGuardProvider) Name() string {
	if p.label == "" {
		return "NordVPN-WG"
	}
	return fmt.Sprintf("NordVPN-WG[%s]", p.label)
}

// HardCap: true — implements multi_vpn_provider.go's hardCapped interface.
// nordWGWeight (main.go) is already a measured real ceiling ("1 account
// sustains exactly 1 WireGuard data path", nordWGDefaultMaxConcurrentConns),
// not a rough guess like most other providers' weights — MultiVPNProvider's
// generic ×vpnCapSlack(3) slack would let it keep routing new attempts to
// an account that's already holding its one real connection, guaranteeing
// the contention failures measured 2026-08-19 (both accounts ~0-20% Acquire
// success under concurrent load, not one bad account — see main.go's
// nordWGWeight doc comment for the full evidence).
func (p *NordVPNWireGuardProvider) HardCap() bool { return true }

func (p *NordVPNWireGuardProvider) Acquire(ctx context.Context, workerID int, emit func(string)) (Lease, error) {
	if emit != nil {
		emit("Đang tìm server NordVPN (WireGuard) khả dụng…")
	}
	return p.acquireLease(ctx, emit)
}

func (p *NordVPNWireGuardProvider) MarkUnhealthyAndRotate(ctx context.Context, workerID int, oldLease Lease, kind FailureKind, emit func(string)) (Lease, error) {
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
		p.mu.Lock()
		slotCh := p.slotChanLocked(t.pubHex)
		p.mu.Unlock()
		<-slotCh // trả lại slot kết nối tunnel này đang giữ, đúng key của nó
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
