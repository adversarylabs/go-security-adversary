package poor

import "log/slog"

func authenticate(token string) {
	slog.Info("authenticated", "token", token)
}
