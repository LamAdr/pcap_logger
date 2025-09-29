Small utility that receive a stream of packets already captured into pcap format over the specified port and log rotate them.
The current log file is rotated at midnight. It is then compressed with gzip's maximum compression level and stored for a specified number of days.

Usage : `go run pcap_logger.go <current file> <archive dir> <port> <days>`
	`<current file>` : Where contemporaneous pcap packets are written
	 `<archive dir>` : Where old pcap packets are compressed and stored
	        `<port>` : Port used to receive pcap packets
	        `<days>` : Number of days the archived packets are stored
