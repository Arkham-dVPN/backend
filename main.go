
package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
)

const (
	ProtocolMDNS = "arkham-vpn-local"
	ProtocolDHT  = "arkham-vpn-global"
	ProtocolStream = "/arkham/vpn/1.0.0"
)

// peerHandler handles the logic for connecting to a newly discovered peer.
// It's designed to be safe to call from multiple goroutines.
func peerHandler(h host.Host, pi peer.AddrInfo) {
	if pi.ID == h.ID() {
		return // Don't connect to ourselves
	}

	// Use a mutex to prevent race conditions when connecting to the same peer from different discovery methods.
	// A more robust solution might use a map with mutexes per peer ID.
	var mu sync.Mutex
	mu.Lock()
	defer mu.Unlock()

	// Check if we are already connected to this peer.
	if h.Network().Connectedness(pi.ID) == network.Connected {
		log.Printf("Already connected to %s", pi.ID)
		return
	}

	log.Printf("Connecting to peer: %s", pi.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := h.Connect(ctx, pi); err != nil {
		log.Printf("Failed to connect to peer %s: %v", pi.ID, err)
		return
	}

	log.Printf("Successfully connected to peer: %s", pi.ID)

	// Open a stream for communication.
	stream, err := h.NewStream(ctx, pi.ID, ProtocolStream)
	if err != nil {
		log.Printf("Failed to open stream to peer %s: %v", pi.ID, err)
		return
	}

	log.Printf("Opened stream to peer: %s", pi.ID)
	msg := fmt.Sprintf("Hello from %s!\n", h.ID().String())
	_, _ = stream.Write([]byte(msg))

	reader := bufio.NewReader(stream)
	response, _ := reader.ReadString('\n')
	log.Printf("Received response: %s", response)
	_ = stream.Close()
}

// discoveryNotifee gets notified when we find a peer via mDNS.
type discoveryNotifee struct {
	h host.Host
}

// HandlePeerFound is the mDNS discovery handler.
func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	log.Printf("Found peer via mDNS: %s", pi.ID.String())
	peerHandler(n.h, pi)
}

// streamHandler handles incoming streams.
func streamHandler(s network.Stream) {
	remotePeer := s.Conn().RemotePeer()
	log.Printf("Received stream from peer: %s", remotePeer)

	reader := bufio.NewReader(s)
	msg, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading from stream: %v", err)
		_ = s.Reset()
		return
	}
	log.Printf("Received message: %s", msg)

	response := fmt.Sprintf("Message received by %s!\n", s.Conn().LocalPeer().String())
	_, _ = s.Write([]byte(response))
	_ = s.Close()
}

func main() {
	ctx := context.Background()

	// Create libp2p host.
	h, err := libp2p.New(
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/0",
			"/ip6/::/tcp/0",
		),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
	)
	if err != nil {
		log.Fatalf("Failed to create libp2p host: %v", err)
	}
	defer h.Close()

	log.Printf("Arkham Node Initialized")
	log.Printf("Peer ID: %s", h.ID().String())
	log.Printf("Listening addresses:")
	for _, addr := range h.Addrs() {
		log.Printf("  %s/p2p/%s", addr, h.ID().String())
	}

	h.SetStreamHandler(ProtocolStream, streamHandler)

	// --- Setup mDNS for Local Discovery ---
	log.Println("Setting up local peer discovery (mDNS)...")
	mdnsService := mdns.NewMdnsService(h, ProtocolMDNS, &discoveryNotifee{h: h})
	if err := mdnsService.Start(); err != nil {
		log.Fatalf("Failed to start mDNS service: %v", err)
	}
	defer mdnsService.Close()

	// --- Setup DHT for Global Discovery ---
	log.Println("Setting up global peer discovery (DHT)...")
	kdht, err := kaddht.New(ctx, h)
	if err != nil {
		log.Fatalf("Failed to create DHT: %v", err)
	}

	log.Println("Bootstrapping the DHT...")
	if err = kdht.Bootstrap(ctx); err != nil {
		log.Fatalf("Failed to bootstrap DHT: %v", err)
	}

	// Announce our presence on the DHT
	log.Println("Announcing ourselves on the DHT...")
	routingDiscovery := routing.NewRoutingDiscovery(kdht)
	util.Advertise(ctx, routingDiscovery, ProtocolDHT)
	log.Println("Successfully announced!")

	// Find peers on the DHT in a background goroutine
	go func() {
		for {
			log.Println("Searching for peers on the DHT...")
			peerChan, err := routingDiscovery.FindPeers(ctx, ProtocolDHT)
			if err != nil {
				log.Printf("Failed to find peers on DHT: %v", err)
				time.Sleep(1 * time.Minute)
				continue
			}
			for p := range peerChan {
				log.Printf("Found peer via DHT: %s", p.ID.String())
				peerHandler(h, p)
			}
			// Search again after a delay
			time.Sleep(1 * time.Minute)
		}
	}()

	log.Println("Node is running. Discovering peers via mDNS and DHT.")
	log.Println("Press Ctrl+C to exit")

	select {}
}
