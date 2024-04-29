package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

type Device struct {
	IP    string       `json:"ip"`
	MAC   string       `json:"mac"`
	Port  int          `json:"port"`
	Name  string       `json:"name"`
	Ports map[int]bool `json:"ports"`
}

func (d Device) String() string {
	var parts []string

	if d.Name != "" {
		parts = append(parts, "Name: "+d.Name)
	}

	if d.IP != "" {
		parts = append(parts, "IP: "+d.IP)
	}

	if d.MAC != "" {
		parts = append(parts, "MAC: "+d.MAC)
	}

	if d.Port != 0 {
		parts = append(parts, "Port: "+strconv.Itoa(d.Port))
	}

	res := strings.Join(parts, ", ")
	if len(d.Ports) != 0 {
		res += "\nPORTS:\n"

		keys := make([]int, 0, len(d.Ports))
		for k := range d.Ports {
			keys = append(keys, k)
		}

		sort.Ints(keys)
		for _, port := range keys {
			res += fmt.Sprintf("\t%-5s: %5t\n", strconv.Itoa(port), d.Ports[port])
		}
	}

	return res
}

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

func main() {
	devices, err := scan("192.168.0.0/24")
	if err != nil {
		return
	}

	for _, device := range devices {
		fmt.Println(device)
	}
}

func scan(targets string) ([]Device, error) {
	var devices []Device
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a new nmap scanner
	scanner, err := nmap.NewScanner(
		ctx,
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

		ports := PortPing(ip,
			[]int{20, 21, 22, 80, 135, 139, 143, 443, 445, 3020, 3306, 3389, 8022, 8080},
		)

		devices = append(devices, Device{
			Port:  0,
			IP:    ip,
			MAC:   mac,
			Name:  name,
			Ports: ports,
		})
	}

	return devices, nil
}
