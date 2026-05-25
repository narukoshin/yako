//go:build unix

package config

import "os"

func readPlatformMachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(p)
		if err == nil && len(data) >= 32 {
			return string(data[:32])
		}
	}
	return ""
}
