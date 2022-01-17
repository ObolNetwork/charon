module github.com/obolnetwork/charon

go 1.17

require (
	github.com/drand/kyber v1.1.9
	github.com/drand/kyber-bls12381 v0.2.1
	github.com/ethereum/go-ethereum v1.10.10
	github.com/golang/protobuf v1.5.2
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.0.1
	github.com/libp2p/go-libp2p v0.17.0
	github.com/libp2p/go-libp2p-core v0.13.0
	github.com/libp2p/go-libp2p-noise v0.3.0
	github.com/multiformats/go-multiaddr v0.5.0
	github.com/prysmaticlabs/eth2-types v0.0.0-20210303084904-c9735a06829d
	github.com/prysmaticlabs/prysm v1.4.4
	github.com/rs/zerolog v1.26.1
	github.com/spf13/cobra v1.3.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.10.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	google.golang.org/genproto v0.0.0-20211208223120-3a66f561d7aa
	google.golang.org/grpc v1.43.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.2.0
	google.golang.org/protobuf v1.27.1
)

// See https://github.com/prysmaticlabs/grpc-gateway/issues/2
replace github.com/grpc-ecosystem/grpc-gateway/v2 => github.com/prysmaticlabs/grpc-gateway/v2 v2.3.1-0.20210702154020-550e1cd83ec1

require (
	github.com/google/uuid v1.3.0
	github.com/ipfs/go-cid v0.1.0 // indirect
	github.com/ipfs/go-log/v2 v2.5.0 // indirect
	github.com/klauspost/compress v1.14.1 // indirect
	github.com/libp2p/go-addr-util v0.2.0 // indirect
	github.com/libp2p/go-libp2p-autonat v0.8.0 // indirect
	github.com/miekg/dns v1.1.45 // indirect
	github.com/multiformats/go-base32 v0.0.4 // indirect
	github.com/multiformats/go-multihash v0.1.0 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prysmaticlabs/prysm/v2 v2.0.1
	github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4 v1.2.0
	go.uber.org/automaxprocs v1.4.0
	go.uber.org/zap v1.20.0 // indirect
	golang.org/x/crypto v0.0.0-20220112180741-5e0467b6c7ce // indirect
	golang.org/x/net v0.0.0-20220111093109-d55c255bac03 // indirect
	golang.org/x/sys v0.0.0-20220111092808-5a964db01320 // indirect
	golang.org/x/tools v0.1.8 // indirect
	lukechampine.com/blake3 v1.1.7 // indirect
)
