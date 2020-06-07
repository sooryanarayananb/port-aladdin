package main

import (
	"fmt"

	"github.com/sooryanarayananb/port-aladdin/port"
)

func main() {
	fmt.Println("Aladdin Scanning Vulnerable Ports")
	fmt.Println()
	results := port.MostVulnerablePorts("localhost")

	for i := 0; i < len(results); i++ {
		fmt.Println(results[i].Port + ":" + results[i].State)
		fmt.Println()
	}

}
