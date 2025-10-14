package main

import (
	"context"
	"log"
	"sync"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"

	kaddht "github.com/libp2p/go-libp2p-kad-dht"
)

// Rendezvous is a unique string that identifies our application on the network.
const Rendezvous = "arkham-vpn-network"

func main() {
	ctx := context.Background()

	// Create a new libp2p Host.
	h, err := libp2p.New(
		// Listen on all available interfaces on a random port.
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
	)
	if err != nil {
		log.Fatalf("Failed to create libp2p host: %v", err)
	}
	log.Printf("Arkham Node Initialized with Peer ID: %s", h.ID().String())
	log.Printf("Listening on: %v", h.Addrs())

	// Start a DHT, for use in peer discovery.
	// The default bootstrap peers are from IPFS, which is a good starting point.
	kdht, err := kaddht.New(ctx, h)
	if err != nil {
		log.Fatalf("Failed to create DHT: %v", err)
	}

	// Bootstrap the DHT. In the default configuration, this spawns a background
	// thread that will refresh the peer table every five minutes.
	log.Println("Bootstrapping the DHT...")
	if err = kdht.Bootstrap(ctx); err != nil {
		log.Fatalf("Failed to bootstrap DHT: %v", err)
	}

	// Let's connect to the bootstrap nodes first. They will tell us about the other nodes in the network.
	var wg sync.WaitGroup
	for _, p := range kaddht.DefaultBootstrapPeers {
		pi, err := peer.AddrInfoFromP2pAddr(p)
		if err != nil {
			log.Printf("Could not parse bootstrap peer: %s, error: %v", p, err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.Connect(ctx, *pi); err != nil {
				log.Printf("Failed to connect to bootstrap peer: %s, error: %v", pi.ID, err)
			} else {
				log.Printf("Connection established with bootstrap peer: %s", pi.ID)
			}
		}()
	}
	wg.Wait()

	// We use a routing discovery mechanism to advertise our presence and find other peers.
	log.Println("Announcing our presence...")
	routingDiscovery := routing.NewRoutingDiscovery(kdht)
	util.Advertise(ctx, routingDiscovery, Rendezvous)
	log.Println("Successfully announced!")

	// Now, look for other peers.
	log.Println("Searching for other Arkham nodes...")
	peerChan, err := routingDiscovery.FindPeers(ctx, Rendezvous)
	if err != nil {
		log.Fatalf("Failed to find peers: %v", err)
	}

	for p := range peerChan {
		// Ignore self
		if p.ID == h.ID() {
			continue
		}

		log.Printf("Found Arkham peer: %s", p.ID.String())
		// Here is where you would establish a connection and potentially a WireGuard tunnel.
		// For now, we'll just log that we found them.
	}

	log.Println("Peer discovery complete. Node is running.")

	// Keep the application running.
	select {}
}