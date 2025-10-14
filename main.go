package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
)

const (
	ProtocolMDNS       = "arkham-vpn-local"
	ProtocolDHT        = "arkham-vpn-global"
	ProtocolStream     = "/arkham/vpn/1.0.0"
	WireGuardInterface = "wg0"
)

// --- Data Structures --- //

type VPNRequest struct {
	SeekerPublicKey string `json:"seeker_public_key"`
}

type VPNResponse struct {
	WardenPublicKey string `json:"warden_public_key"`
}

type APIResponse struct {
	Status          string `json:"status"`
	Message         string `json:"message"`
	WardenPeerID    string `json:"warden_peer_id,omitempty"`
	SeekerPublicKey string `json:"seeker_public_key,omitempty"`
	WardenPublicKey string `json:"warden_public_key,omitempty"`
}

// PeerInfo holds detailed information about a discovered peer for the API
type PeerInfo struct {
	ID    string   `json:"id"`
	Addrs []string `json:"addrs"`
}

// --- P2P Logic --- //

func streamHandler(s network.Stream) {
	remotePeer := s.Conn().RemotePeer()
	log.Printf("[WARDEN] Received VPN request from Seeker: %s", remotePeer)

	var req VPNRequest
	if err := json.NewDecoder(s).Decode(&req); err != nil {
		log.Printf("[WARDEN] Failed to decode request: %v", err)
		_ = s.Reset()
		return
	}

	wardenPrivKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Printf("[WARDEN] Failed to generate key: %v", err)
		_ = s.Reset()
		return
	}

	resp := VPNResponse{WardenPublicKey: wardenPrivKey.PublicKey().String()}
	if err := json.NewEncoder(s).Encode(resp); err != nil {
		log.Printf("[WARDEN] Failed to send response: %v", err)
		_ = s.Reset()
		return
	}

	log.Printf("✅ [WARDEN] VPN Tunnel negotiated for Seeker %s!", remotePeer)
}

// --- API Handlers --- //

func peersHandler(w http.ResponseWriter, r *http.Request, h host.Host) {
	peers := h.Peerstore().Peers()
	var peerInfos []PeerInfo

	for _, p := range peers {
		if p == h.ID() {
			continue
		}

		addrs := h.Peerstore().Addrs(p)
		addrStrings := make([]string, len(addrs))
		for i, addr := range addrs {
			addrStrings[i] = addr.String()
		}

		peerInfos = append(peerInfos, PeerInfo{
			ID:    p.String(),
			Addrs: addrStrings,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(peerInfos)
}

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
		writeError(w, http.StatusServiceUnavailable, "No available peers found.")
		return
	}

	log.Printf("[API] Attempting to negotiate tunnel with %s", wardenPeer)

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	seekerPrivKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate private key.")
		return
	}

	stream, err := h.NewStream(ctx, wardenPeer, ProtocolStream)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to open stream to peer: %v", err))
		return
	}

	req := VPNRequest{SeekerPublicKey: seekerPrivKey.PublicKey().String()}
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to send request: %v", err))
		return
	}

	var resp VPNResponse
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get response: %v", err))
		return
	}

	log.Printf("✅ [API] Successfully negotiated keys with %s", wardenPeer)

	log.Printf("[API] Applying configuration to local interface '%s'...", WireGuardInterface)
	if err := configureSeekerInterface(seekerPrivKey, resp.WardenPublicKey, stream.Conn()); err != nil {
		log.Printf("[API] Error configuring WireGuard interface: %v", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to configure WireGuard interface: %v. Try running with sudo?", err))
		return
	}

	log.Printf("✅ [API] Successfully configured WireGuard interface '%s'!", WireGuardInterface)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(APIResponse{
		Status:          "success",
		Message:         fmt.Sprintf("WireGuard interface '%s' configured.", WireGuardInterface),
		WardenPeerID:    wardenPeer.String(),
		SeekerPublicKey: seekerPrivKey.PublicKey().String(),
		WardenPublicKey: resp.WardenPublicKey,
	})
}

func configureSeekerInterface(privKey wgtypes.Key, wardenPubKeyStr string, conn network.Conn) error {
	cmd := exec.Command("ip", "link", "add", WireGuardInterface, "type", "wireguard")
	if err := cmd.Run(); err != nil {
		log.Printf("Could not create interface '%s' (it may already exist): %v", WireGuardInterface, err)
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl client: %w", err)
	}
	defer wgClient.Close()

	wardenPubKey, err := wgtypes.ParseKey(wardenPubKeyStr)
	if err != nil {
		return fmt.Errorf("failed to parse warden public key: %w", err)
	}

	addr, _ := multiaddr.NewMultiaddr(strings.Split(conn.RemoteMultiaddr().String(), "/quic-v1")[0])
	remoteAddr, err := manet.ToNetAddr(addr)
	if err != nil {
		return fmt.Errorf("failed to parse remote multiaddr: %w", err)
	}

	udpAddr := remoteAddr.(*net.UDPAddr)

	peer := wgtypes.PeerConfig{
		PublicKey: wardenPubKey,
		AllowedIPs: []net.IPNet{
			{IP: net.ParseIP("0.0.0.0"), Mask: net.CIDRMask(0, 32)},
		},
		Endpoint: udpAddr,
	}

	cfg := wgtypes.Config{
		PrivateKey:   &privKey,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{peer},
	}

	log.Printf("Attempting to configure device '%s' with peer %s", WireGuardInterface, wardenPubKey.String())
	return wgClient.ConfigureDevice(WireGuardInterface, cfg)
}

func writeError(w http.ResponseWriter, code int, message string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(APIResponse{Status: "error", Message: message})
}

// --- Main Application Setup --- //

func main() {
	peerOnly := flag.Bool("peer-only", false, "Runs the node without the API server.")
	flag.Parse()

	h, err := libp2p.New(libp2p.EnableRelay(), libp2p.EnableHolePunching())
	if err != nil {
		log.Fatalf("Failed to create libp2p host: %v", err)
	}
	defer h.Close()

	log.Printf("Arkham P2P Node Initialized: %s", h.ID().String())
	h.SetStreamHandler(ProtocolStream, streamHandler)

	go setupDiscovery(h)

	if !*peerOnly {
		log.Println("Starting API server on :8080...")
		http.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			peersHandler(w, r, h)
		})
		http.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			connectHandler(w, r, h)
		})
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("Failed to start API server: %v", err)
		}
	} else {
		log.Println("Running in peer-only mode.")
		select {}
	}
}

func setupDiscovery(h host.Host) {
	ctx := context.Background()

	mdnsService := mdns.NewMdnsService(h, ProtocolMDNS, &discoveryNotifee{h: h})
	if err := mdnsService.Start(); err != nil {
		log.Printf("mDNS start error: %v", err)
	}

	kdht, err := kaddht.New(ctx, h)
	if err != nil {
		log.Printf("DHT create error: %v", err)
		return
	}
	if err = kdht.Bootstrap(ctx); err != nil {
		log.Printf("DHT bootstrap error: %v", err)
		return
	}

	routingDiscovery := routing.NewRoutingDiscovery(kdht)
	util.Advertise(ctx, routingDiscovery, ProtocolDHT)

	go func() {
		for {
			peerChan, _ := routingDiscovery.FindPeers(ctx, ProtocolDHT)
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