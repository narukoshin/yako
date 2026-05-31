//go:build unix

package config

import "os"

// readPlatformMachineID reads the machine ID from /etc/machine-id or
// /var/lib/dbus/machine-id on Linux/Unix systems.
func readPlatformMachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(p)
		if err == nil && len(data) >= 32 {
			return string(data[:32])
		}
	}
	return ""
}
