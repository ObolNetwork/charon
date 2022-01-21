package config

const (
	KeyDataDir     = "data-dir"
	KeyClustersDir = "clusters-dir"
	KeyConfigFile  = "config-file"
	KeyBeaconNode  = "beacon-node"
	KeyLogLevel    = "log-level"
	KeyAPI         = "api"
	KeyVerbose     = "verbose"
	KeyValidators  = "validators"
)

type P2PConfig struct {
	Address   string
	TcpPort   int
	UdpPort   int
	AllowList []string
	DenyList  []string
}

type MonitoringConfig struct {
	Address string
	Port    int
}

type ValidatorApiConfig struct {
	Address string
	Port    int
}

type BeaconNodeConfig struct {
	Endpoint []string
}

type RunnerConfig struct {
	BeaconNodeUrl   string
	ControlPlaneApi MonitoringConfig
	DataDir         string
	LogLevel        string
	VerboseFlag     bool
	ClusterConfig
}

type ClusterConfig struct {
	ClusterFilepath     string
	CertificateFilepath string
	PrivateKeyFilepath  string
	PrivateKeyPassword  string
}
