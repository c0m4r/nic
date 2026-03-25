package dhcp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// nativeClient tracks a running native DHCP session for one interface.
type nativeClient struct {
	iface   string
	cancel  context.CancelFunc
	done    chan struct{}
	lease   *Lease
	leaseV6 *LeaseV6
	mu      sync.Mutex
}

var (
	nativeClients   = make(map[string]*nativeClient)
	nativeClientsMu sync.Mutex
)

func startNative(iface string) error {
	stopNative(iface)

	ctx, cancel := context.WithCancel(context.Background())
	nc := &nativeClient{
		iface:  iface,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	nativeClientsMu.Lock()
	nativeClients[iface] = nc
	nativeClientsMu.Unlock()

	// Run DHCPv4 and DHCPv6 in parallel
	var wg sync.WaitGroup
	var v4err, v6err error
	var v4lease *Lease
	var v6lease *LeaseV6

	wg.Add(1)
	go func() {
		defer wg.Done()
		v4lease, v4err = runDHCPv4(ctx, iface)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		v6lease, v6err = runDHCPv6(ctx, iface)
	}()

	// Wait for both with a timeout
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(30 * time.Second):
		cancel()
		<-waitDone
	}

	// Apply whatever we got
	applied := false

	if v4err == nil && v4lease != nil {
		if err := applyLease(iface, v4lease); err != nil {
			fmt.Printf("dhcp v4: apply failed: %v\n", err)
		} else {
			nc.mu.Lock()
			nc.lease = v4lease
			nc.mu.Unlock()
			_ = v4lease.save()
			applied = true
			fmt.Printf("dhcp: %s got %s via %s (lease %ds)\n",
				iface, v4lease.CIDR(), v4lease.Router, v4lease.LeaseTime)
		}
	}

	if v6err == nil && v6lease != nil {
		if err := applyLeaseV6(iface, v6lease); err != nil {
			fmt.Printf("dhcp v6: apply failed: %v\n", err)
		} else {
			nc.mu.Lock()
			nc.leaseV6 = v6lease
			nc.mu.Unlock()
			_ = v6lease.save()
			applied = true
			for _, addr := range v6lease.Addresses {
				fmt.Printf("dhcp: %s got %s/%d (v6, valid %ds)\n",
					iface, addr.IP, addr.PrefixLen, addr.ValidLife)
			}
		}
	}

	if !applied {
		cancel()
		nativeClientsMu.Lock()
		delete(nativeClients, iface)
		nativeClientsMu.Unlock()

		// Return the most informative error
		if v4err != nil {
			return fmt.Errorf("dhcp v4: %w", v4err)
		}
		if v6err != nil {
			return fmt.Errorf("dhcp v6: %w", v6err)
		}
		return fmt.Errorf("dhcp: no lease obtained on %s", iface)
	}

	// Start renewal goroutine
	go nc.renewLoop(ctx)

	return nil
}

func (nc *nativeClient) renewLoop(ctx context.Context) {
	defer close(nc.done)

	for {
		nc.mu.Lock()
		lease := nc.lease
		leaseV6 := nc.leaseV6
		nc.mu.Unlock()

		// Pick the earliest renewal deadline
		var nextRenew time.Time

		if lease != nil {
			t := lease.RenewalDeadline()
			if nextRenew.IsZero() || t.Before(nextRenew) {
				nextRenew = t
			}
		}

		if leaseV6 != nil && len(leaseV6.Addresses) > 0 {
			// Use preferred lifetime / 2 for renewal
			addr := leaseV6.Addresses[0]
			t := leaseV6.AcquiredAt.Add(time.Duration(addr.PreferredLife/2) * time.Second)
			if nextRenew.IsZero() || t.Before(nextRenew) {
				nextRenew = t
			}
		}

		if nextRenew.IsZero() {
			return // no leases to renew
		}

		wait := time.Until(nextRenew)
		if wait < time.Second {
			wait = time.Second
		}

		select {
		case <-ctx.Done():
			nc.release()
			return
		case <-time.After(wait):
		}

		// Renew DHCPv4
		if lease != nil && time.Now().After(lease.RenewalDeadline()) {
			newLease, err := renewLease(nc.iface, lease)
			if err != nil {
				fmt.Printf("dhcp: v4 renew failed: %v\n", err)
				// Try rebind at T2
				if time.Now().After(lease.RebindDeadline()) {
					// Lease expiring, try full DORA
					newLease, err = runDHCPv4(ctx, nc.iface)
					if err != nil {
						fmt.Printf("dhcp: v4 rebind failed: %v\n", err)
						continue
					}
				} else {
					continue
				}
			}
			unapplyLease(nc.iface, lease)
			if err := applyLease(nc.iface, newLease); err == nil {
				nc.mu.Lock()
				nc.lease = newLease
				nc.mu.Unlock()
				_ = newLease.save()
			}
		}

		// Renew DHCPv6
		if leaseV6 != nil {
			mac, _, err := getIfaceInfo(nc.iface)
			if err == nil {
				duid := newDUID(mac)
				newLease, err := renewLeaseV6(nc.iface, leaseV6, duid)
				if err != nil {
					fmt.Printf("dhcp: v6 renew failed: %v\n", err)
					continue
				}
				unapplyLeaseV6(nc.iface, leaseV6)
				if err := applyLeaseV6(nc.iface, newLease); err == nil {
					nc.mu.Lock()
					nc.leaseV6 = newLease
					nc.mu.Unlock()
					_ = newLease.save()
				}
			}
		}
	}
}

func (nc *nativeClient) release() {
	nc.mu.Lock()
	lease := nc.lease
	leaseV6 := nc.leaseV6
	nc.mu.Unlock()

	// Send RELEASE for v4
	if lease != nil {
		mac, _, err := getIfaceInfo(nc.iface)
		if err == nil {
			serverIP := net.ParseIP(lease.ServerIP)
			clientIP := net.ParseIP(lease.IP)
			if serverIP != nil && clientIP != nil {
				release := buildRelease(mac, clientIP, serverIP)
				conn, err := net.DialTimeout("udp4", lease.ServerIP+":67", 2*time.Second)
				if err == nil {
					_, _ = conn.Write(release)
					_ = conn.Close()
				}
			}
		}
		unapplyLease(nc.iface, lease)
		removeLease(nc.iface)
	}

	// Send RELEASE for v6
	if leaseV6 != nil {
		mac, _, err := getIfaceInfo(nc.iface)
		if err == nil {
			duid := newDUID(mac)
			var addrs []iaAddrInfo
			for _, a := range leaseV6.Addresses {
				addrs = append(addrs, iaAddrInfo{IP: net.ParseIP(a.IP)})
			}
			var txID [3]byte
			release := buildReleaseV6(duid, leaseV6.ServerDUID, leaseV6.IAID, txID, addrs)
			conn, err := net.ListenPacket("udp6", "[::]:546")
			if err == nil {
				dst := &net.UDPAddr{
					IP:   dhcpv6ServerAddr.IP,
					Port: dhcpv6ServerAddr.Port,
					Zone: nc.iface,
				}
				_, _ = conn.WriteTo(release, dst)
				_ = conn.Close()
			}
		}
		unapplyLeaseV6(nc.iface, leaseV6)
		removeLeaseV6(nc.iface)
	}
}

func stopNative(iface string) {
	nativeClientsMu.Lock()
	nc, ok := nativeClients[iface]
	if ok {
		delete(nativeClients, iface)
	}
	nativeClientsMu.Unlock()

	if ok {
		nc.cancel()
		<-nc.done
	}
}

func stopAllNative() {
	nativeClientsMu.Lock()
	clients := make(map[string]*nativeClient, len(nativeClients))
	for k, v := range nativeClients {
		clients[k] = v
	}
	nativeClients = make(map[string]*nativeClient)
	nativeClientsMu.Unlock()

	for _, nc := range clients {
		nc.cancel()
		<-nc.done
	}
}

func statusNative(iface string) string {
	nativeClientsMu.Lock()
	nc, ok := nativeClients[iface]
	nativeClientsMu.Unlock()

	if !ok {
		return ""
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()

	parts := []string{"native dhcp"}
	if nc.lease != nil {
		parts = append(parts, fmt.Sprintf("v4=%s", nc.lease.CIDR()))
	}
	if nc.leaseV6 != nil && len(nc.leaseV6.Addresses) > 0 {
		parts = append(parts, fmt.Sprintf("v6=%s", nc.leaseV6.Addresses[0].IP))
	}

	result := parts[0]
	for _, p := range parts[1:] {
		result += " " + p
	}
	return result
}
