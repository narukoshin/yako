//go:build windows

package config

import "golang.org/x/sys/windows/registry"

// readPlatformMachineID reads the MachineGuid from the Windows registry.
// Every Windows install has one — Microsoft made sure of that.
func readPlatformMachineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()

	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return guid
}
