package option

type RouteOptions struct {
	GeoIP                *GeoIPOptions   `json:"geoip,omitempty"`
	Geosite              *GeositeOptions `json:"geosite,omitempty"`
	Rules                []Rule          `json:"rules,omitempty"`
	RuleSet              []RuleSet       `json:"rule_set,omitempty"`
	Final                string          `json:"final,omitempty"`
	StopAlwaysResolveUDP bool            `json:"stop_always_resolve_udp,omitempty"`
	FindProcess          *bool           `json:"find_process,omitempty"`
	AutoDetectInterface  bool            `json:"auto_detect_interface,omitempty"`
	OverrideAndroidVPN   bool            `json:"override_android_vpn,omitempty"`
	DefaultInterface     string          `json:"default_interface,omitempty"`
	DefaultMark          uint32          `json:"default_mark,omitempty"`
	ConcurrentDial       bool            `json:"concurrent_dial,omitempty"`
	KeepAliveInterval    Duration        `json:"keep_alive_interval,omitempty"`
}

type GeoIPOptions struct {
	Path           string `json:"path,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
	DownloadDetour string `json:"download_detour,omitempty"`
}

type GeositeOptions struct {
	Path           string `json:"path,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
	DownloadDetour string `json:"download_detour,omitempty"`
}
