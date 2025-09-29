package main

import (
	"net"
	"log"
	"os"
	"time"
	"path/filepath"
	"io"
	"encoding/binary"
	"sync"
	"compress/gzip"
	"bufio"
	"io/ioutil"
	"strconv"
	"fmt"
)

func rotate(
	current_file *os.File,
	mu *sync.Mutex,
	next_file chan<- *os.File,
	current_path string,
	archive_dir string,
	globalHeader []byte,
	days int,
) {
	// Get time and sleep duration
	time_layout := "2006-01-02"
	now := time.Now()
	location := now.Location()
	tomorrow := now.AddDate(0, 0, 1)
	tomorrow = time.Date(tomorrow.Year(), tomorrow.Month(), tomorrow.Day(), 0, 0, 0, 0, location)
	sleep_time := tomorrow.Sub(now)

	// Sleep
	time.Sleep(sleep_time)
	now = tomorrow

	mu.Lock()

	// Archive current log file using timestamp from sleeper routine
	current_file.Close()
	current_base := filepath.Base(current_path)
	archive_path := current_base + "." + now.Format(time_layout)
	tmp_path := filepath.Join(archive_dir, archive_path)
	err := os.Rename(current_path, tmp_path)
	if err != nil {
		log.Fatal(err)
	}

	// Create new current log and initialize it with the PCAP global header
	current_file, err = os.Create(current_path)
	if err != nil {
		log.Fatal(err)
	}
	_, err = current_file.Write(globalHeader)
	if err != nil {
		log.Fatal(err)
	}

	next_file <- current_file

	mu.Unlock()

	// Compress rotated log
	tmp, err := os.Open(tmp_path)
	if err != nil {
		log.Fatal(err)
	}

	read := bufio.NewReader(tmp)
	data, err := ioutil.ReadAll(read)
	if err != nil {
		log.Fatal(err)
	}
	tmp.Close()
	err = os.Remove(tmp_path)
	if err != nil {
		log.Fatal(err)
	}

	rotated_path := tmp_path + ".gz"
	rotated, err := os.Create(rotated_path)
	if err != nil {
		log.Fatal(err)
	}

	gzip_writer, err := gzip.NewWriterLevel(rotated, gzip.BestCompression)
	if err != nil {
		log.Fatal(err)
	}
	gzip_writer.Write(data)
	gzip_writer.Close()
	rotated.Close()

	// Remove old logs
	rm_time := now.AddDate(0, 0, -days)
	rm_path := current_base + "." + rm_time.Format(time_layout) + ".gz"
	rm_path = filepath.Join(archive_dir, rm_path)
	if _, err := os.Stat(rm_path); err == nil {
		err = os.Remove(rm_path)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func main() {

	// Parse command
	if len(os.Args) != 5 {
		fmt.Println("Usage : go run pcap_logger.go <current file> <archive dir> <port> <days>")
		fmt.Println("\t<current file> : Where contemporaneous pcap packets are written")
		fmt.Println("\t <archive dir> : Where old pcap packets are compressed and stored")
		fmt.Println("\t        <port> : Port used to receive pcap packets")
		fmt.Println("\t        <days> : Number of days the archived packets are stored")
		return
	}
 	current_path := os.Args[1]
	archive_dir := os.Args[2]
	port := os.Args[3]
	days, err := strconv.Atoi(os.Args[4])
 	if err != nil {
 		log.Fatal(err)
 	}

	err = os.MkdirAll(archive_dir, os.ModePerm)
 	if err != nil {
 		log.Fatal(err)
 	}

	// Create current log
 	current_file, err := os.Create(current_path)
 	if err != nil {
 		log.Fatal(err)
 	}

	// Pointer to the next file when the previous has been archived
	next_file := make(chan *os.File, 1)
	var mu sync.Mutex

	// Start listener
 	l, err := net.Listen("tcp", ":"+port)
 	if err != nil {
 		log.Fatal(err)
 	}
 	defer l.Close()

	// Accept one connection
 	conn, err := l.Accept()
 	if err != nil {
 		log.Fatal(err)
 	}

	// Receive PCAP global header
	globalHeader := make([]byte, 24)
	if _, err := io.ReadFull(conn, globalHeader); err != nil {
		log.Fatal(err)
	}

	// Identify endianness
	magic := binary.LittleEndian.Uint32(globalHeader[0:4])
	var endian binary.ByteOrder
	switch magic {
	case 0xa1b2c3d4:
		endian = binary.LittleEndian
	case 0xd4c3b2a1:
		endian = binary.BigEndian
	default:
		log.Fatalf("Unknown PCAP magic: 0x%x", magic)
	}

	// Write global header to file
	_, err = current_file.Write(globalHeader)
	if err != nil {
		log.Fatal(err)
	}

	// Start sleeper for one day
	go rotate(
		current_file,
		&mu,
		next_file,
		current_path,
		archive_dir,
		globalHeader,
		days,
	)

	for {
		// Read packet header
		packetHeader := make([]byte, 16)
		_, err := io.ReadFull(conn, packetHeader)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		// Extract packet length
		caplen := endian.Uint32(packetHeader[8:12])

		// Read packet data
		packetData := make([]byte, caplen)
		_, err = io.ReadFull(conn, packetData)
		if err != nil {
			log.Fatal(err)
		}

		mu.Lock()

		select {
		// If file has been rotated
		case current_file = <-next_file:
			// Start a new sleeper routine
			go rotate(
				current_file,
				&mu,
				next_file,
				current_path,
				archive_dir,
				globalHeader,
				days,
			)
		default:
		}

		// Write PCAP to log file
		packet := append(packetHeader, packetData...)
		_, err = current_file.Write(packet)
		if err != nil {
			log.Fatal(err)
		}

		mu.Unlock()
	}
}
