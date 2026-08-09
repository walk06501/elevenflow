package webview2bridge

// Hand-verified IPVanish WireGuard configs (2026-08-09), each generated via
// IPVanish's own "Generate for me" flow (no Custom Public Key), one real
// dedicated key per server - see ipvanish_wireguard_provider.go's doc
// comment for why this is the only model confirmed to actually work.
// Grow this list by hand a few at a time, never in a scripted burst.
var ipvanishServerList = [...]ipvanishServer{
	{Name: "AT-Vienna-vie-c12", PrivateKeyB64: "xGEpohAMd5xEfgMduB0tWLj5CBfBE88tYoyAJplDNoc=", Address: "100.96.2.255", PublicKeyB64: "h/VV5+1/zLyOgWKY5wqVqKSXEKsDBjMmOi9IEmqwlFE=", Host: "216.131.110.166", Port: "51820"},
	{Name: "AU-Sydney-syd-c01", PrivateKeyB64: "R/O+/dfNSZMEl/Ek+mCXUVdaE/dQhB2Y+r+kuA25v5U=", Address: "100.96.0.95", PublicKeyB64: "HDMLOfE29u9lzqSuDiChXbsB1AiWUoglYlLFP6yC4V4=", Host: "36.255.205.3", Port: "51820"},
	{Name: "AU-Perth-per-c08", PrivateKeyB64: "FEHeD4KuyaHrHvmsGrT4CUFYTBSOSLyQYVE1ZmCPcnQ=", Address: "100.96.0.29", PublicKeyB64: "ZiyeOVxdZtn+JCTQGFHS3hgQckiUySkrK9bXwVaWolo=", Host: "103.107.196.70", Port: "51820"},
	{Name: "AU-Brisbane-bne-c09", PrivateKeyB64: "mtCVmR/LVtiZhTULQk7i5zS7m7hB9X07Q1+hpS7zGdI=", Address: "100.96.0.17", PublicKeyB64: "kWXvhIT8z6AOR7URwy441XFj7+KRqYF+Lx4docjNGHs=", Host: "103.62.50.234", Port: "51820"},
	{Name: "AU-Adelaide-adl-c06", PrivateKeyB64: "aVzQtPA3WEKsVvK89I9sumngAJtNuMTvF3ChJb7DKCI=", Address: "100.96.1.231", PublicKeyB64: "/wd7KGR/Tgi1q5HF5catUFbk5C/BhdaDM0VST0Wd+Ro=", Host: "116.90.73.23", Port: "51820"},
}
