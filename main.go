
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
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

// --- Data Structures for API and P2P --- //

type VPNRequest struct {
	SeekerPublicKey string `json:"seeker_public_key"`
}

type VPNResponse struct {
	WardenPublicKey string `json:"warden_public_key"`
}

// APIResponse is the structure returned by our /api/connect endpoint
type APIResponse struct {
	Status          string `json:"status"`
	Message         string `json:"message"`
	WardenPeerID    string `json:"warden_peer_id,omitempty"`
	SeekerPublicKey string `json:"seeker_public_key,omitempty"`
	WardenPublicKey string `json:"warden_public_key,omitempty"`
}

// --- P2P Logic --- //

// streamHandler handles incoming VPN requests (as a Warden).
func streamHandler(s network.Stream) {
	remotePeer := s.Conn().RemotePeer()
	log.Printf("[WARDEN] Received VPN request from Seeker: %s", remotePeer)

	var req VPNRequest
	if err := json.NewDecoder(s).Decode(&req); err != nil {
		log.Printf("[WARDEN] Failed to decode request from %s: %v", remotePeer, err)
		_ = s.Reset()
		return
	}

	wardenPrivKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Printf("[WARDEN] Failed to generate WireGuard key: %v", err)
		_ = s.Reset()
		return
	}
	wardenPubKey := wardenPrivKey.PublicKey().String()

	resp := VPNResponse{WardenPublicKey: wardenPubKey}
	if err := json.NewEncoder(s).Encode(resp); err != nil {
		log.Printf("[WARDEN] Failed to send response to %s: %v", remotePeer, err)
		_ = s.Reset()
		return
	}

	log.Printf("✅ [WARDEN] VPN Tunnel negotiated for Seeker %s!", remotePeer)
}

// --- API Handlers --- //

func connectHandler(w http.ResponseWriter, r *http.Request, h host.Host) {
	log.Println("[API] Received /api/connect request")

	var wardenPeer peer.ID
	if len(h.Peerstore().Peers()) > 1 {
		for _, p := range h.Peerstore().Peers() {
			if p != h.ID() {
				wardenPeer = p
				break
			}
		}
	}

	if wardenPeer == "" {
		log.Println("[API] No peers found to connect to.")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(APIResponse{Status: "error", Message: "No available peers found."})
		return
	}

	log.Printf("[API] Attempting to negotiate tunnel with %s", wardenPeer)

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	seekerPrivKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Status: "error", Message: "Failed to generate private key."})
		return
	}
	seekerPubKey := seekerPrivKey.PublicKey().String()

	stream, err := h.NewStream(ctx, wardenPeer, ProtocolStream)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Status: "error", Message: fmt.Sprintf("Failed to open stream to peer: %v", err)})
		return
	}

	req := VPNRequest{SeekerPublicKey: seekerPubKey}
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Status: "error", Message: fmt.Sprintf("Failed to send request: %v", err)})
		return
	}

	var resp VPNResponse
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Status: "error", Message: fmt.Sprintf("Failed to get response: %v", err)})
		return
	}

	log.Printf("✅ [API] Successfully negotiated tunnel with %s", wardenPeer)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(APIResponse{
		Status:          "success",
		Message:         "VPN Tunnel Negotiated",
		WardenPeerID:    wardenPeer.String(),
		SeekerPublicKey: seekerPubKey,
		WardenPublicKey: resp.WardenPublicKey,
	})
}

// --- Main Application Setup --- //

func main() {
	peerOnly := flag.Bool("peer-only", false, "Runs the node without the API server to act as a simple peer.")
	flag.Parse()

	h, err := libp2p.New(
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
	)
	if err != nil {
		log.Fatalf("Failed to create libp2p host: %v", err)
	}
	defer h.Close()

	log.Printf("Arkham P2P Node Initialized with Peer ID: %s", h.ID().String())
	h.SetStreamHandler(ProtocolStream, streamHandler)

	go setupDiscovery(h)

	if !*peerOnly {
		log.Println("Starting API server on :8080...")
		http.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			connectHandler(w, r, h)
		})
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("Failed to start API server: %v", err)
		}
	} else {
		log.Println("Running in peer-only mode. API server not started.")
		select {}
	}
}

func setupDiscovery(h host.Host) {
	ctx := context.Background()

	mdnsService := mdns.NewMdnsService(h, ProtocolMDNS, &discoveryNotifee{h: h})
	if err := mdnsService.Start(); err != nil {
		log.Printf("Failed to start mDNS service: %v", err)
	}

	kdht, err := kaddht.New(ctx, h)
	if err != nil {
		log.Printf("Failed to create DHT: %v", err)
		return
	}
	if err = kdht.Bootstrap(ctx); err != nil {
		log.Printf("Failed to bootstrap DHT: %v", err)
		return
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
			// Passively add peers to the peerstore
			for p := range peerChan {
				if p.ID != h.ID() {
					h.Peerstore().AddAddrs(p.ID, p.Addrs, time.Hour)
				}
			}
			time.Sleep(1 * time.Minute)
		}
	}()

	log.Println("Discovery services running.")
}

type discoveryNotifee struct {
	h host.Host
}

func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.h.ID() {
		return
	}
	log.Printf("Found peer via mDNS: %s", pi.ID.String())
	n.h.Peerstore().AddAddrs(pi.ID, pi.Addrs, time.Hour)
}
