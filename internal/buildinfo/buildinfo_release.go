//go:build !dev

package buildinfo

const Mode = "production"

// SharedProxyLease: true = một lease chung (Luna). false = mỗi worker một dòng
// proxy (xoay 1ip / gói có changeip — cần ≥ số worker dòng is_active).
const SharedProxyLease = false

// MaxTTSWorkers / MinTTSWorkers: trần và sàn số luồng WebView2 (autoscale và khi tắt autoscale).
const MaxTTSWorkers = 3
const MinTTSWorkers = 2

// AutoScaleWorkersToProxyPool: trước mỗi batch (khi không SharedProxyLease), gọi
// GET /api/proxy/capacity; NumWorkers = max(MinTTSWorkers, min(MaxTTSWorkers, pool_count, max_leases)).
const AutoScaleWorkersToProxyPool = true
