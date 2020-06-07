package port

import (
	"net"
	"strconv"
	"sync"
	"time"
)

type ScanResult struct {
	Port  string
	State string
}

func ScanPort(protocol, hostname string, port int) ScanResult {
	result := ScanResult{Port: strconv.Itoa(port) + string("/") + protocol}
	address := hostname + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout(protocol, address, 60*time.Second)

	if err != nil {
		result.State = "Closed"
		return result
	}
	defer conn.Close()
	result.State = "Open"
	return result
}

func MostVulnerablePorts(hostname string) []ScanResult {
	var results []ScanResult
	vulnerablePorts := []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}

	var wg sync.WaitGroup
	wg.Add(len(vulnerablePorts))

	for i := 0; i < len(vulnerablePorts); i++ {
		go func(i int) {
			defer wg.Done()
			results = append(results, ScanPort("tcp", hostname, vulnerablePorts[i]))
		}(i)
	}

	wg.Wait()
	return results

}

//Incase you need to use wide scan for udp and tcp.
func WideScan(hostname string) []ScanResult {
	var results []ScanResult

	for i := 0; i <= 49152; i++ {
		results = append(results, ScanPort("udp", hostname, i))
	}

	for i := 0; i <= 49152; i++ {
		results = append(results, ScanPort("tcp", hostname, i))
	}

	return results
}
