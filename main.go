package main

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
)

const (
	ProtocolMDNS   = "arkham-vpn-local"
	ProtocolDHT    = "arkham-vpn-global"
	ProtocolStream = "/arkham/vpn/1.0.0"
)

// VPNRequest is sent by the Seeker to the Warden
type VPNRequest struct {
	SeekerPublicKey string `json:"seeker_public_key"`
}

// VPNResponse is sent by the Warden back to the Seeker
type VPNResponse struct {
	WardenPublicKey string `json:"warden_public_key"`
}

// peerHandler is the logic for connecting to a newly discovered peer (as a Seeker).
func peerHandler(h host.Host, pi peer.AddrInfo) {
	if pi.ID == h.ID() {
		return // Don't connect to ourselves
	}

	var mu sync.Mutex
	mu.Lock()
	defer mu.Unlock()

	if h.Network().Connectedness(pi.ID) == network.Connected {
		return // Already connected or have a pending connection
	}

	log.Printf("[SEEKER] Found potential Warden: %s. Attempting to connect...", pi.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := h.Connect(ctx, pi); err != nil {
		log.Printf("[SEEKER] Failed to connect to %s: %v", pi.ID, err)
		return
	}

	log.Printf("[SEEKER] Connection established to %s. Negotiating tunnel...", pi.ID)

	// 1. Generate our own WireGuard key pair
	seekerPrivKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Printf("[SEEKER] Failed to generate WireGuard private key: %v", err)
		return
	}
	seekerPubKey := seekerPrivKey.PublicKey().String()

	// 2. Open a stream to the Warden to send our public key
	stream, err := h.NewStream(ctx, pi.ID, ProtocolStream)
	if err != nil {
		log.Printf("[SEEKER] Failed to open stream to %s: %v", pi.ID, err)
		return
	}

	// 3. Create and send the VPNRequest
	req := VPNRequest{SeekerPublicKey: seekerPubKey}
	encoder := json.NewEncoder(stream)
	if err := encoder.Encode(req); err != nil {
		log.Printf("[SEEKER] Failed to send request to %s: %v", pi.ID, err)
		_ = stream.Reset()
		return
	}

	// 4. Wait for the Warden's response
	decoder := json.NewDecoder(stream)
	var resp VPNResponse
	if err := decoder.Decode(&resp); err != nil {
		log.Printf("[SEEKER] Failed to receive response from %s: %v", pi.ID, err)
		_ = stream.Reset()
		return
	}

	log.Printf("✅ [SEEKER] VPN Tunnel negotiated with Warden %s!", pi.ID)
	log.Printf("  - My Private Key: %s", seekerPrivKey.String())
	log.Printf("  - My Public Key: %s", seekerPubKey)
	log.Printf("  - Warden Public Key: %s", resp.WardenPublicKey)
	log.Println("  --- Configuration would be applied to local WireGuard interface --- ")

	_ = stream.Close()
}

// streamHandler handles incoming VPN requests (as a Warden).
func streamHandler(s network.Stream) {
	remotePeer := s.Conn().RemotePeer()
	log.Printf("[WARDEN] Received VPN request from Seeker: %s", remotePeer)

	// 1. Decode the Seeker's request
	decoder := json.NewDecoder(s)
	var req VPNRequest
	if err := decoder.Decode(&req); err != nil {
		log.Printf("[WARDEN] Failed to decode request from %s: %v", remotePeer, err)
		_ = s.Reset()
		return
	}
	log.Printf("[WARDEN] Received public key from Seeker: %s", req.SeekerPublicKey)

	// 2. Generate our own WireGuard key pair
	wardenPrivKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Printf("[WARDEN] Failed to generate WireGuard key: %v", err)
		_ = s.Reset()
		return
	}
	wardenPubKey := wardenPrivKey.PublicKey().String()

	// 3. Create and send the response
	resp := VPNResponse{WardenPublicKey: wardenPubKey}
	encoder := json.NewEncoder(s)
	if err := encoder.Encode(resp); err != nil {
		log.Printf("[WARDEN] Failed to send response to %s: %v", remotePeer, err)
		_ = s.Reset()
		return
	}

	log.Printf("✅ [WARDEN] VPN Tunnel negotiated for Seeker %s!", remotePeer)
	log.Printf("  - My Private Key: %s", wardenPrivKey.String())
	log.Printf("  - My Public Key: %s", wardenPubKey)
	log.Printf("  - Seeker Public Key: %s", req.SeekerPublicKey)
	log.Println("  --- Configuration would be applied to local WireGuard interface --- ")

	_ = s.Close()
}

func main() {
	ctx := context.Background()

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
	mdnsService := mdns.NewMdnsService(h, ProtocolMDNS, &discoveryNotifee{h: h})
	if err := mdnsService.Start(); err != nil {
		log.Fatalf("Failed to start mDNS service: %v", err)
	}
	defer mdnsService.Close()

	// --- Setup DHT for Global Discovery ---
	kdht, err := kaddht.New(ctx, h)
	if err != nil {
		log.Fatalf("Failed to create DHT: %v", err)
	}
	if err = kdht.Bootstrap(ctx); err != nil {
		log.Fatalf("Failed to bootstrap DHT: %v", err)
	}
	routingDiscovery := routing.NewRoutingDiscovery(kdht)
	util.Advertise(ctx, routingDiscovery, ProtocolDHT)

	go func() {
		for {
			peerChan, err := routingDiscovery.FindPeers(ctx, ProtocolDHT)
			if err != nil {
				time.Sleep(1 * time.Minute)
				continue
			}
			for p := range peerChan {
				peerHandler(h, p)
			}
			time.Sleep(1 * time.Minute)
		}
	}()

	log.Println("Node is running. Press Ctrl+C to exit")
	select {}
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