package good

import "crypto/tls"

func config() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS13} }
