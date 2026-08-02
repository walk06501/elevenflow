//go:build dev

package buildinfo

const Mode = "development"

const SharedProxyLease = false

const MaxTTSWorkers = 3
const MinTTSWorkers = 2

const AutoScaleWorkersToProxyPool = true
