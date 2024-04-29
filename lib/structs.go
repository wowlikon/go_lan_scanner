package lib

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var PortList = []int{
	20, 21, 22, 80, 135, 139, 143, 443, 445, 3020, 3306, 3389, 8022, 8080,
}

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
