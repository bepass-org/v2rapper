package main

import (
	"bufio"
	"container/list"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const _maxLogMessages = 100
const maxBufferSize = 4096

// Account for other content above the logs, adjust this value as needed
const otherContentLines = 2

var (
	bindAddress  string
	localTarget  string
	remoteTarget string
	paths        pathList

	countryWhitelist pathList
	countryBlacklist pathList
	cidrList         []*net.IPNet
	uploadSpeedStr   string
	downloadSpeedStr string

	maxUploadSpeed   int64
	maxDownloadSpeed int64

	currentBytesUp   int64
	currentBytesDown int64

	connections    sync.Map
	acceptingConns bool
	acceptLock     sync.Mutex
	lastCheck      time.Time

	logList        *list.List // Linked list for log messages
	logsMutex      sync.Mutex // Mutex to protect the logs array
	terminalMutex  = &sync.Mutex{}
	maxLogMessages = _maxLogMessages
)

// logWriter implements io.Writer by sending the log output to the logMessages channel
type logWriter struct{}

func logMessage(message string) {
	logsMutex.Lock()
	defer logsMutex.Unlock()

	// Get the terminal width
	width, _, err := terminal.GetSize(int(syscall.Stdout))
	if err != nil {
		fmt.Println("error getting terminal size:", err)
		width = 80 // Default if the terminal size can't be determined
	}

	width -= 1 // Account for the newline character

	// Split the message on newlines
	parts := strings.Split(message, "\n")

	for _, part := range parts {
		// If the part is longer than the terminal width, break it into smaller parts
		for len(part) > width {
			smallerPart := part[:width]
			logList.PushBack(smallerPart)
			part = part[width:]

			// If we exceed the max log messages, remove the oldest one
			if logList.Len() > maxLogMessages {
				logList.Remove(logList.Front())
			}
		}

		// Add the remaining part (or the original part if it was shorter than the width)
		logList.PushBack(part)

		// If we exceed the max log messages, remove the oldest one
		if logList.Len() > maxLogMessages {
			logList.Remove(logList.Front())
		}
	}
}

func (logWriter) Write(p []byte) (n int, err error) {
	logMessage(strings.TrimSpace(string(p)))
	return len(p), nil
}

func init() {
	flag.StringVar(&bindAddress, "bind", ":8080", "The address to bind the TCP server to. (shorthand -b)")
	flag.StringVar(&bindAddress, "b", ":8080", "(shorthand for --bind)")

	flag.StringVar(&localTarget, "local", "127.0.0.1:8081", "The ip:port to forward to if the connection matches a path. (shorthand -l)")
	flag.StringVar(&localTarget, "l", "127.0.0.1:8081", "(shorthand for --local)")

	flag.StringVar(&remoteTarget, "remote", "google.com:443", "The ip:port to forward to if the connection does not match any paths. (shorthand -r)")
	flag.StringVar(&remoteTarget, "r", "google.com:443", "(shorthand for --remote)")

	flag.StringVar(&uploadSpeedStr, "upload-speed", "10MB", "Maximum upload speed (e.g., 10MB, 10Mb, 10KB). (shorthand -us)")
	flag.StringVar(&uploadSpeedStr, "us", "10MB", "(shorthand for --upload-speed)")

	flag.StringVar(&downloadSpeedStr, "download-speed", "10MB", "Maximum download speed (e.g., 10MB, 10Mb, 10KB). (shorthand -ds)")
	flag.StringVar(&downloadSpeedStr, "ds", "10MB", "(shorthand for --download-speed)")

	flag.Var(&paths, "path", "The string to check in the incoming connection to determine routing. Can be specified multiple times. (shorthand -p)")
	flag.Var(&paths, "p", "(shorthand for --path)")

	flag.Var(&countryWhitelist, "country-whitelist", "List of country codes to whitelist (can be specified multiple times). (shorthand -cw)")
	flag.Var(&countryWhitelist, "cw", "(shorthand for --country-whitelist)")

	flag.Var(&countryBlacklist, "country-blacklist", "List of country codes to blacklist (can be specified multiple times). (shorthand -cb)")
	flag.Var(&countryBlacklist, "cb", "(shorthand for --country-blacklist)")

	// Initialize the log list
	_, m, err := terminal.GetSize(int(syscall.Stdout))
	if err != nil {
		maxLogMessages = _maxLogMessages // Fallback if the terminal size can't be determined
	}
	maxLogMessages = m
	logList = list.New()
}

type pathList []string

func (p *pathList) String() string {
	return strings.Join(*p, ",")
}

func (p *pathList) Set(value string) error {
	*p = append(*p, value)
	return nil
}

func main() {
	help := flag.Bool("help", false, "Display help message. (shorthand -h)")
	flag.BoolVar(help, "h", false, "(shorthand for --help)")

	flag.Parse()

	if *help {
		flag.Usage()
		return
	}
	// Ensure that both whitelist and blacklist are not set simultaneously
	if len(countryWhitelist) > 0 && len(countryBlacklist) > 0 {
		fmt.Println("Error: country whitelist and blacklist cannot be set simultaneously.")
		os.Exit(1)
	}

	// Download CIDRs based on the provided country codes
	var err error
	err = downloadCIDRs(countryWhitelist, countryBlacklist)
	if err != nil {
		fmt.Printf("Error downloading CIDRs: %v\n", err)
		os.Exit(1)
	}

	clearScreen()
	defer clearScreen() // Clear the screen before the program exits.

	// Redirect standard logger to the logMessages channel
	log.SetOutput(logWriter{})

	maxUploadSpeed = parseSpeed(uploadSpeedStr)
	maxDownloadSpeed = parseSpeed(downloadSpeedStr)

	acceptingConns = true
	go trackSpeeds()
	go displaySpeeds()

	listener, err := net.Listen("tcp", bindAddress)
	if err != nil {
		log.Printf("Error listening: %v\n", err)
		return
	}
	defer listener.Close()
	log.Println("Listening on " + bindAddress)

	for {
		if conn := acceptConnection(listener); conn != nil {
			connections.Store(conn, true)
			go handleRequest(conn)
		}
	}
}

func downloadContent(url, code string) error {
	response, err := http.Get(url)
	if response.StatusCode != 200 {
		err = fmt.Errorf("failed to download CIDR for country code %s: %d", code, response.StatusCode)
	}
	if err != nil {
		return fmt.Errorf("failed to download CIDR for country code %s: %w", code, err)
	}
	defer response.Body.Close()

	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		_, cidr, _ := net.ParseCIDR(scanner.Text())
		cidrList = append(cidrList, cidr)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read CIDR for country code %s: %w", code, err)
	}
	return nil
}

func downloadCIDRs(whitelist, blacklist pathList) error {
	var countryCodes pathList
	if len(whitelist) > 0 {
		countryCodes = whitelist
	} else if len(blacklist) > 0 {
		countryCodes = blacklist
	} else {
		return nil // No filtering needed
	}

	for _, code := range countryCodes {
		code = strings.ToLower(code)
		err := downloadContent("https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/"+code+".cidr", code)
		if err != nil {
			return err
		}
		err = downloadContent("https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv6/"+code+".cidr", code)
		if err != nil {
			return err
		}
	}
	return nil
}

func displaySpeeds() {
	for {
		// Move the cursor to the top of the current terminal window
		clearScreen()
		fmt.Print("\033[H\033[2K")

		// Calculate the speeds
		now := time.Now()
		duration := now.Sub(lastCheck).Seconds()

		uploadSpeed := float64(atomic.LoadInt64(&currentBytesUp)) / duration
		downloadSpeed := float64(atomic.LoadInt64(&currentBytesUp)) / duration
		totalSpeed := uploadSpeed + downloadSpeed

		terminalMutex.Lock()

		fmt.Printf("Upload: %s, Download: %s, Total: %s\n",
			humanReadableSpeed(int64(uploadSpeed)),
			humanReadableSpeed(int64(downloadSpeed)),
			humanReadableSpeed(int64(totalSpeed)))

		printPendingLogs()

		terminalMutex.Unlock()

		time.Sleep(250 * time.Millisecond)
	}
}

func printPendingLogs() {
	maxLogs := maxLogMessages - otherContentLines

	// Print the logs from newest to oldest
	for e, i := logList.Front(), 0; e != nil && i < maxLogs; e, i = e.Next(), i+1 {
		fmt.Println(e.Value.(string))
	}

	_, m, err := terminal.GetSize(int(syscall.Stdout))
	if err != nil {
		maxLogMessages = _maxLogMessages // Fallback if the terminal size can't be determined
	}
	maxLogMessages = m
}

func clearScreen() {
	fmt.Print("\033[H\033[2J") // Clear the entire screen and move the cursor to the top-left corner.
}

func humanReadableSpeed(bytesPerSecond int64) string {
	const (
		_          = iota // ignore first value by assigning to blank identifier
		KB float64 = 1 << (10 * iota)
		MB
		GB
	)

	speed := float64(bytesPerSecond)
	switch {
	case speed >= GB:
		return fmt.Sprintf("%.2f GB/s", speed/GB)
	case speed >= MB:
		return fmt.Sprintf("%.2f MB/s", speed/MB)
	case speed >= KB:
		return fmt.Sprintf("%.2f KB/s", speed/KB)
	default:
		return fmt.Sprintf("%d B/s", bytesPerSecond)
	}
}

func acceptConnection(listener net.Listener) net.Conn {
	acceptLock.Lock()
	defer acceptLock.Unlock()
	if !acceptingConns {
		return nil
	}

	conn, err := listener.Accept()
	if err != nil {
		log.Printf("Error accepting: %v\n", err)
		return nil
	}
	return conn
}

func shouldBlockConnection(ip net.IP) bool {
	for _, cidr := range cidrList {
		if (isIPv4(ip) && isIPv4(cidr.IP)) || (!isIPv4(ip) && !isIPv4(cidr.IP)) {
			if cidr.Contains(ip) {
				return len(countryBlacklist) > 0 // Block if in blacklist mode and IP is found
			}
		}
	}
	return len(countryWhitelist) > 0 // Block if in whitelist mode and IP is not found
}

// Helper function to check if an IP is IPv4.
func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

func handleRequest(conn net.Conn) {
	buffer := make([]byte, maxBufferSize)

	n, err := conn.Read(buffer)
	if err != nil {
		log.Println("Error reading:", err)
		return
	}
	buffer = buffer[:n]

	// If whitelist or blacklist is enabled, check the incoming IP
	if len(cidrList) > 0 {
		remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
		if shouldBlockConnection(remoteAddr.IP) {
			log.Println("Fella requested from", conn.RemoteAddr(),
				" but get blocked, its request content was:", cleanString(buffer))
			forceReset(conn) // Refuse the connection
			return
		}
	}

	target := determineTarget(buffer, conn.RemoteAddr())
	forwardConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("Error connecting to target: %v\n", err)
		return
	}
	defer forwardConn.Close()

	_, err = forwardConn.Write(buffer)
	if err != nil {
		log.Println("Error writing to target:", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go proxy(&wg, conn, forwardConn, &currentBytesUp)
	go proxy(&wg, forwardConn, conn, &currentBytesDown)

	wg.Wait() // Wait for both proxy goroutines to complete before closing connections.
	forceReset(conn)
}

func forceReset(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetLinger(0) // Set SO_LINGER to 0 with a timeout of 0 to force a TCP RST.
		tcpConn.Close()
	}
}

func proxy(wg *sync.WaitGroup, src, dst net.Conn, currentBytes *int64) {
	defer wg.Done()

	buf := make([]byte, 32*1024) // 32KB buffer size

	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[0:nr])
			if writeErr != nil {
				// Handle the write error
				break
			}
			if nw > 0 {
				// Update the current interval's byte count
				atomic.AddInt64(currentBytes, int64(nw))
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				// Handle the read error
			}
			break
		}
	}
}

func cleanString(b []byte) string {
	var result strings.Builder
	for _, c := range b {
		if c >= 32 && c <= 126 { // ASCII printable characters
			result.WriteByte(c)
		} else {
			result.WriteString(fmt.Sprintf("\\x%02x", c)) // Represent non-printables as hex
		}
	}
	return result.String()
}

func determineTarget(initialData []byte, remoteAddr net.Addr) string {
	for _, path := range paths {
		if strings.Contains(string(initialData), path) {
			log.Println("A new connection from", remoteAddr, "and requested", path, "so we'll forward them to", localTarget)
			return localTarget
		}
	}
	log.Println("Malicious fella connected from", remoteAddr, "and requested", cleanString(initialData), "so we'll forward them to", remoteTarget)
	return remoteTarget
}

func parseSpeed(speedStr string) int64 {
	cleanedSpeedStr := strings.ToUpper(strings.ReplaceAll(speedStr, " ", ""))
	cleanedSpeedStr = strings.ReplaceAll(cleanedSpeedStr, "/S", "")
	cleanedSpeedStr = strings.ReplaceAll(cleanedSpeedStr, "/PS", "")

	re := regexp.MustCompile(`(\d+)([KMGT]?B?)`)
	matches := re.FindStringSubmatch(cleanedSpeedStr)

	if len(matches) != 3 {
		log.Printf("Invalid speed format: %s\n", speedStr)
		return 0
	}

	number, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		log.Printf("Invalid speed number: %s\n", matches[1])
		return 0
	}

	var multiplier int64 = 1
	switch matches[2] {
	case "KB":
		multiplier = 1024
	case "MB":
		multiplier = 1024 * 1024
	case "GB":
		multiplier = 1024 * 1024 * 1024
	case "K", "KBPS", "KB/S":
		multiplier = 1000
	case "M", "MBPS", "MB/S":
		multiplier = 1000 * 1000
	case "G", "GBPS", "GB/S":
		multiplier = 1000 * 1000 * 1000
	case "B":
		multiplier = 1
	case "":
		multiplier = 1
	}

	return number * multiplier
}

func trackSpeeds() {
	lastCheck = time.Now()

	for {
		time.Sleep(1 * time.Second)

		now := time.Now()
		duration := now.Sub(lastCheck).Seconds()

		uploadSpeed := float64(atomic.LoadInt64(&currentBytesUp)) / duration
		downloadSpeed := float64(atomic.LoadInt64(&currentBytesDown)) / duration

		if uploadSpeed > float64(maxUploadSpeed) || downloadSpeed > float64(maxDownloadSpeed) {
			dropOldConns()
			stopAcceptingConns()
		} else {
			startAcceptingConns()
		}

		atomic.StoreInt64(&currentBytesUp, 0)
		atomic.StoreInt64(&currentBytesDown, 0)
		lastCheck = now
	}
}

func dropOldConns() {
	connections.Range(func(k, v interface{}) bool {
		conn := k.(net.Conn)
		conn.Close()
		connections.Delete(conn)
		return true
	})
}

func stopAcceptingConns() {
	acceptLock.Lock()
	acceptingConns = false
	acceptLock.Unlock()
}

func startAcceptingConns() {
	acceptLock.Lock()
	acceptingConns = true
	acceptLock.Unlock()
}
