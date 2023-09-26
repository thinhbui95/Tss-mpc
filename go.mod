module github.com/bnb-chain/tss-lib/v2

go 1.16

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412
	github.com/btcsuite/btcd v0.23.4
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/btcsuite/btcutil v0.0.0-20190425235716-9e5f4b9a998d
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.0
	github.com/ethereum/go-ethereum v1.13.1 // indirect
	github.com/hashicorp/go-multierror v1.0.0
	github.com/ipfs/go-log v1.0.5
	github.com/otiai10/mint v1.2.4 // indirect
	github.com/otiai10/primes v0.0.0-20180210170552-f6d2a1ba97c4
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.4
	github.com/ubiq/go-ubiq v3.0.1+incompatible // indirect
	github.com/whyrusleeping/go-logging v0.0.0-20170515211332-0457bb6b88fc // indirect
	golang.org/x/crypto v0.12.0
	google.golang.org/protobuf v1.27.1
)

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
