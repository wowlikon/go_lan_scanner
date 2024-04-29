package main

import (
	"fmt"

	s "github.com/wowlikon/go_lan_scanner/lib"
)

func main() {
	devices, err := s.Scan("192.168.0.0/24", s.PortList)
	if err != nil {
		return
	}

	for _, device := range devices {
		fmt.Println(device)
	}
}
