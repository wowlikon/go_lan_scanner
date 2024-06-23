package lib

import (
	"net"
	"strconv"
	"time"

	"github.com/Ullaakut/nmap"
)

func PortPing(ip string, ports []int) map[int]bool {
	results := make(map[int]bool)
	for _, port := range ports {
		address := net.JoinHostPort(ip, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, time.Second/2)
		if err != nil {
			results[port] = false
		} else {
			if conn != nil {
				results[port] = true
				_ = conn.Close()
			} else {
				results[port] = false
			}
		}
	}
	return results
}

func Scan(targets string, ports []int) ([]Device, error) {
	var devices []Device

	// Create a new nmap scanner
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targets), // Specify the network range to scan
		nmap.WithFastMode(),       // Enable fast mode
	)

	if err != nil {
		return nil, err
	}

	// Run the scan
	result, _, err := scanner.Run()
	if err != nil {
		return nil, err
	}

	// Print the results
	for _, host := range result.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}

		ip := host.Addresses[0].Addr

		name := "Unknown"
		if len(host.Hostnames) >= 1 {
			name = host.Hostnames[0].Name
		}

		mac := ""
		if len(host.Addresses) > 1 {
			mac = host.Addresses[1].Addr
		}

		free_ports := PortPing(
			ip, ports,
		)

		devices = append(devices, Device{
			Port:  0,
			IP:    ip,
			MAC:   mac,
			Name:  name,
			Ports: free_ports,
		})
	}

	return devices, nil
}
