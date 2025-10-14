
package main

import (
	"log"

	"github.com/libp2p/go-libp2p"
)

func main() {
	// Create a new libp2p Host
	// Listen on all available interfaces on a random port
	host, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
	)
	if err != nil {
		log.Fatalf("Failed to create libp2p host: %v", err)
	}

	log.Printf("Arkham Node Initialized!")
	log.Printf("My Peer ID is: %s", host.ID().String())
	log.Printf("Listening on addresses: %v", host.Addrs())

	// Keep the application running
	select {}
}
