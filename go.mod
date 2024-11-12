module github.com/sagernet/sing-box

go 1.20

require (
	berty.tech/go-libtor v1.0.385
	github.com/Dreamacro/clash v1.17.0
	github.com/caddyserver/certmagic v0.20.0
	github.com/cloudflare/circl v1.3.7
	github.com/cretz/bine v0.2.0
	github.com/dlclark/regexp2 v1.11.4
	github.com/go-chi/chi/v5 v5.0.12
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/render v1.0.3
	github.com/gofrs/uuid/v5 v5.2.0
	github.com/hjson/hjson-go/v4 v4.4.0
	github.com/insomniacslk/dhcp v0.0.0-20231206064809-8c70d406f6d2
	github.com/libdns/alidns v1.0.3
	github.com/libdns/cloudflare v0.1.1
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/mholt/acmez v1.2.0
	github.com/miekg/dns v1.1.61
	github.com/ooni/go-libtor v1.1.8
	github.com/oschwald/maxminddb-golang v1.12.0
	github.com/sagernet/bbolt v0.0.0-20231014093535-ea5cb2fe9f0a
	github.com/sagernet/cloudflare-tls v0.0.0-20231208171750-a4483c1b7cd1
	github.com/sagernet/fswatch v0.1.1
	github.com/sagernet/gomobile v0.1.3
	github.com/sagernet/gvisor v0.0.0-20240428053021-e691de28565f
	github.com/sagernet/quic-go v0.46.0-beta.2
	github.com/sagernet/reality v0.0.0-20230406110435-ee17307e7691
	github.com/sagernet/sing v0.5.0-alpha.15
	github.com/sagernet/sing-dns v0.3.0-beta.14
	github.com/sagernet/sing-mux v0.2.0
	github.com/sagernet/sing-quic v0.2.0-beta.12
	github.com/sagernet/sing-shadowsocks v0.2.7
	github.com/sagernet/sing-shadowsocks2 v0.2.0
	github.com/sagernet/sing-shadowtls v0.1.4
	github.com/sagernet/sing-tun v0.4.0-beta.13.0.20240703164908-1f043289199d
	github.com/sagernet/sing-vmess v0.1.12
	github.com/sagernet/smux v0.0.0-20231208180855-7041f6ea79e7
	github.com/sagernet/tfo-go v0.0.0-20231209031829-7b5343ac1dc6
	github.com/sagernet/utls v1.5.4
	github.com/sagernet/websocket v0.0.0-20220913015213-615516348b4e
	github.com/sagernet/wireguard-go v0.0.0-20231215174105-89dec3b2f3e8
	github.com/spf13/cobra v1.8.0
	github.com/stretchr/testify v1.9.0
	github.com/titanous/json5 v1.0.0
	go.uber.org/zap v1.27.0
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.25.0
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56
	golang.org/x/net v0.27.0
	golang.org/x/sys v0.22.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
	google.golang.org/grpc v1.63.2
	google.golang.org/protobuf v1.33.0
	gopkg.in/yaml.v3 v3.0.1
	howett.net/plist v1.0.1
)

replace github.com/sagernet/sing-dns v0.3.0-beta.14 => github.com/puernya/sing-dns v0.0.0-20240815232643-6fdfdcca8106

replace github.com/sagernet/sing v0.5.0-alpha.15 => github.com/puernya/sing v0.0.0-20240813154738-7869f22b3a64

replace github.com/sagernet/sing-tun v0.4.0-beta.13.0.20240703164908-1f043289199d => github.com/puernya/sing-tun v0.0.0-20240814031813-21dee280e97a

replace github.com/sagernet/websocket => github.com/shioeri/websocket v1.6.0-alpha.3

//replace github.com/sagernet/sing => ../sing

require (
	github.com/Dreamacro/protobytes v0.0.0-20230617041236-6500a9f4f158 // indirect
	github.com/ajg/form v1.5.1 // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20231101202521-4ca4178f5c7a // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/libdns/libdns v0.2.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/onsi/ginkgo/v2 v2.9.7 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.4.1 // indirect
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a // indirect
	github.com/sagernet/nftables v0.3.0-beta.4 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/mod v0.19.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.23.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240227224415-6ceb2ff114de // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)