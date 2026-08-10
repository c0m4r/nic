package dhcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/c0m4r/nic/internal/executor"
)

// nativeClient tracks a running native DHCP session for one interface.
type nativeClient struct {
	iface   string
	v6      bool
	cancel  context.CancelFunc
	done    chan struct{}
	lease   *Lease
	leaseV6 *LeaseV6
	retryAt time.Time
	mu      sync.Mutex
}

var (
	nativeClients   = make(map[string]*nativeClient)
	nativeClientsMu sync.Mutex
)

func startNative(iface string, daemonMode bool) error {
	stopNativeKey(iface)
	if err := ensureInterfaceUp(iface); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(executor.CommandContext())
	nc := &nativeClient{
		iface:  iface,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	nativeClientsMu.Lock()
	nativeClients[iface] = nc
	nativeClientsMu.Unlock()

	acquireCtx, acquireCancel := context.WithTimeout(ctx, 30*time.Second)
	defer acquireCancel()

	v4lease, v4err := runDHCPv4(acquireCtx, iface)

	if v4err != nil || v4lease == nil {
		finishFailedStart(iface, nc)
		if v4err != nil {
			return fmt.Errorf("dhcp v4: %w", v4err)
		}
		return fmt.Errorf("dhcp: no v4 lease on %s", iface)
	}

	if err := applyLease(iface, v4lease); err != nil {
		fmt.Printf("%s: apply failed: %v\n", iface, err)
		finishFailedStart(iface, nc)
		return fmt.Errorf("%s: %w", iface, err)
	}

	nc.mu.Lock()
	nc.lease = v4lease
	nc.mu.Unlock()
	_ = v4lease.save()

	if daemonMode {
		go nc.renewLoop(ctx)
	} else {
		finishOneShot(iface, nc)
	}
	return nil
}

func startNativeV6(iface string, daemonMode bool) error {
	key := iface + ":6"
	stopNativeKey(key)
	if err := ensureInterfaceUp(iface); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(executor.CommandContext())
	nc := &nativeClient{
		iface:  iface,
		v6:     true,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	nativeClientsMu.Lock()
	nativeClients[key] = nc
	nativeClientsMu.Unlock()

	acquireCtx, acquireCancel := context.WithTimeout(ctx, 30*time.Second)
	defer acquireCancel()

	v6lease, v6err := runDHCPv6(acquireCtx, iface)

	if v6err != nil || v6lease == nil {
		finishFailedStart(key, nc)
		if v6err != nil {
			return fmt.Errorf("dhcp v6: %w", v6err)
		}
		return fmt.Errorf("dhcp: no v6 lease on %s", iface)
	}

	if err := applyLeaseV6(iface, v6lease); err != nil {
		fmt.Printf("%s: v6 apply failed: %v\n", iface, err)
		finishFailedStart(key, nc)
		return fmt.Errorf("%s: %w", iface, err)
	}

	nc.mu.Lock()
	nc.leaseV6 = v6lease
	nc.mu.Unlock()
	_ = v6lease.save()
	for _, addr := range v6lease.Addresses {
		fmt.Printf("%s: leased %s/%d (v6, valid %ds)\n",
			iface, addr.IP, addr.PrefixLen, addr.ValidLife)
	}

	if daemonMode {
		go nc.renewLoop(ctx)
	} else {
		finishOneShot(key, nc)
	}
	return nil
}

func finishOneShot(key string, nc *nativeClient) {
	nc.cancel()
	nativeClientsMu.Lock()
	delete(nativeClients, key)
	nativeClientsMu.Unlock()
	close(nc.done)
}

func finishFailedStart(key string, nc *nativeClient) {
	nc.cancel()
	nativeClientsMu.Lock()
	delete(nativeClients, key)
	nativeClientsMu.Unlock()
	close(nc.done)
}

func ensureInterfaceUp(iface string) error {
	if _, err := executor.RunIP("link", "set", iface, "up"); err != nil {
		return fmt.Errorf("bring up %s before DHCP: %w", iface, err)
	}
	return nil
}

func (nc *nativeClient) renewLoop(ctx context.Context) {
	defer close(nc.done)

	for {
		nc.mu.Lock()
		lease := nc.lease
		leaseV6 := nc.leaseV6
		retryAt := nc.retryAt
		nc.mu.Unlock()

		nextAction := retryAt
		if nextAction.IsZero() {
			if nc.v6 && leaseV6 != nil {
				nextAction = leaseV6.RenewalDeadline()
			} else if !nc.v6 && lease != nil {
				nextAction = lease.RenewalDeadline()
			}
		}
		if nextAction.IsZero() {
			return // no leases to renew
		}

		wait := time.Until(nextAction)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)

		select {
		case <-ctx.Done():
			timer.Stop()
			nc.release()
			return
		case <-timer.C:
		}

		if nc.v6 {
			nc.maintainV6(ctx, leaseV6)
		} else {
			nc.maintainV4(ctx, lease)
		}
	}
}

const (
	leaseRecoveryRetry   = 5 * time.Second
	leaseRecoveryTimeout = 30 * time.Second
)

func (nc *nativeClient) maintainV4(ctx context.Context, lease *Lease) {
	if lease == nil {
		nc.reacquireV4(ctx)
		return
	}

	now := time.Now()
	if !now.Before(lease.ExpiryDeadline()) {
		nc.expireV4(lease)
		nc.reacquireV4(ctx)
		return
	}
	if now.Before(lease.RenewalDeadline()) {
		return
	}

	var (
		newLease *Lease
		err      error
	)
	if !now.Before(lease.RebindDeadline()) {
		rebindCtx, cancel := context.WithDeadline(ctx, lease.ExpiryDeadline())
		newLease, err = rebindLease(rebindCtx, nc.iface, lease)
		cancel()
	} else {
		newLease, err = renewLease(nc.iface, lease)
	}
	if err != nil {
		fmt.Printf("dhcp: v4 renewal failed: %v\n", err)
		if errors.Is(err, errDHCPv4NAK) {
			nc.expireV4(lease)
			nc.reacquireV4(ctx)
			return
		}
		if !time.Now().Before(lease.ExpiryDeadline()) {
			nc.expireV4(lease)
			return
		}
		nc.scheduleRetry()
		return
	}

	if err := applyLeaseReplacing(nc.iface, newLease, lease); err != nil {
		fmt.Printf("dhcp: v4 apply renewal failed: %v\n", err)
		nc.scheduleRetry()
		return
	}
	cleanupSupersededLease(nc.iface, lease, newLease)
	nc.mu.Lock()
	nc.lease = newLease
	nc.retryAt = time.Time{}
	nc.mu.Unlock()
	_ = newLease.save()
}

func (nc *nativeClient) reacquireV4(ctx context.Context) {
	acquireCtx, cancel := context.WithTimeout(ctx, leaseRecoveryTimeout)
	defer cancel()
	lease, err := runDHCPv4(acquireCtx, nc.iface)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Printf("dhcp: v4 reacquire failed: %v\n", err)
			nc.scheduleRetry()
		}
		return
	}
	if err := applyLease(nc.iface, lease); err != nil {
		fmt.Printf("dhcp: v4 apply reacquired lease failed: %v\n", err)
		nc.scheduleRetry()
		return
	}
	nc.mu.Lock()
	nc.lease = lease
	nc.retryAt = time.Time{}
	nc.mu.Unlock()
	_ = lease.save()
}

func (nc *nativeClient) expireV4(lease *Lease) {
	fmt.Printf("dhcp: v4 lease on %s expired; removing configuration\n", nc.iface)
	unapplyLease(nc.iface, lease)
	removeLease(nc.iface)
	nc.mu.Lock()
	if nc.lease == lease {
		nc.lease = nil
		nc.retryAt = time.Now()
	}
	nc.mu.Unlock()
}

func (nc *nativeClient) maintainV6(ctx context.Context, lease *LeaseV6) {
	if lease == nil {
		nc.reacquireV6(ctx)
		return
	}

	now := time.Now()
	if !now.Before(lease.ExpiryDeadline()) {
		nc.expireV6(lease)
		nc.reacquireV6(ctx)
		return
	}
	if now.Before(lease.RenewalDeadline()) {
		return
	}

	mac, _, err := getIfaceInfo(nc.iface)
	if err != nil {
		fmt.Printf("dhcp: v6 interface identity failed: %v\n", err)
		nc.scheduleRetry()
		return
	}
	duid, err := leaseDUID(lease, mac)
	if err != nil {
		fmt.Printf("dhcp: v6 client identity failed: %v\n", err)
		nc.scheduleRetry()
		return
	}

	var newLease *LeaseV6
	if !now.Before(lease.RebindDeadline()) {
		newLease, err = rebindLeaseV6(nc.iface, lease, duid)
	} else {
		newLease, err = renewLeaseV6(nc.iface, lease, duid)
	}
	if err != nil {
		fmt.Printf("dhcp: v6 renewal failed: %v\n", err)
		if errors.Is(err, errDHCPv6NoAddresses) {
			nc.expireV6(lease)
			nc.reacquireV6(ctx)
			return
		}
		if !time.Now().Before(lease.ExpiryDeadline()) {
			nc.expireV6(lease)
			return
		}
		nc.scheduleRetry()
		return
	}
	if err := applyLeaseV6Replacing(nc.iface, newLease, lease); err != nil {
		fmt.Printf("dhcp: v6 apply renewal failed: %v\n", err)
		nc.scheduleRetry()
		return
	}
	cleanupSupersededLeaseV6(nc.iface, lease, newLease)
	nc.mu.Lock()
	nc.leaseV6 = newLease
	nc.retryAt = time.Time{}
	nc.mu.Unlock()
	_ = newLease.save()
}

func (nc *nativeClient) reacquireV6(ctx context.Context) {
	acquireCtx, cancel := context.WithTimeout(ctx, leaseRecoveryTimeout)
	defer cancel()
	lease, err := runDHCPv6(acquireCtx, nc.iface)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Printf("dhcp: v6 reacquire failed: %v\n", err)
			nc.scheduleRetry()
		}
		return
	}
	if err := applyLeaseV6(nc.iface, lease); err != nil {
		fmt.Printf("dhcp: v6 apply reacquired lease failed: %v\n", err)
		nc.scheduleRetry()
		return
	}
	nc.mu.Lock()
	nc.leaseV6 = lease
	nc.retryAt = time.Time{}
	nc.mu.Unlock()
	_ = lease.save()
}

func (nc *nativeClient) expireV6(lease *LeaseV6) {
	fmt.Printf("dhcp: v6 lease on %s expired; removing configuration\n", nc.iface)
	unapplyLeaseV6(nc.iface, lease)
	removeLeaseV6(nc.iface)
	nc.mu.Lock()
	if nc.leaseV6 == lease {
		nc.leaseV6 = nil
		nc.retryAt = time.Now()
	}
	nc.mu.Unlock()
}

func (nc *nativeClient) scheduleRetry() {
	nc.mu.Lock()
	nc.retryAt = time.Now().Add(leaseRecoveryRetry)
	nc.mu.Unlock()
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
			localAddr, serverAddr, addrErr := v4LeaseUDPAddrs(lease)
			if addrErr == nil {
				release := buildRelease(mac, localAddr.IP, serverAddr.IP)
				conn, err := net.DialUDP("udp4", localAddr, serverAddr)
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
			duid, duidErr := leaseDUID(leaseV6, mac)
			if duidErr != nil {
				fmt.Printf("dhcp: v6 release identity failed: %v\n", duidErr)
			} else {
				var addrs []iaAddrInfo
				for _, a := range leaseV6.Addresses {
					addrs = append(addrs, iaAddrInfo{IP: net.ParseIP(a.IP)})
				}
				txID := randomTxID()
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
		}
		unapplyLeaseV6(nc.iface, leaseV6)
		removeLeaseV6(nc.iface)
	}
}

func stopNativeKey(key string) {
	nativeClientsMu.Lock()
	nc, ok := nativeClients[key]
	if ok {
		delete(nativeClients, key)
	}
	nativeClientsMu.Unlock()

	if ok {
		nc.cancel()
		<-nc.done
	}
}

func stopNative(iface string) {
	stopNativeKey(iface)
	stopNativeKey(iface + ":6")
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

	// Also clean up any leases saved to disk (from a previous process)
	cleanupDiskLeases()
}

// cleanupDiskLeases removes addresses from lease files left by a previous nic process.
func cleanupDiskLeases() {
	entries, err := os.ReadDir(pidDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".lease.json") && !strings.HasSuffix(name, ".v6.lease.json") {
			iface := strings.TrimSuffix(name, ".lease.json")
			data, err := os.ReadFile(filepath.Join(pidDir, name))
			if err != nil {
				continue
			}
			var lease Lease
			if err := json.Unmarshal(data, &lease); err != nil {
				continue
			}
			unapplyLease(iface, &lease)
			_ = os.Remove(filepath.Join(pidDir, name))
		}
		if strings.HasSuffix(name, ".v6.lease.json") {
			iface := strings.TrimSuffix(name, ".v6.lease.json")
			data, err := os.ReadFile(filepath.Join(pidDir, name))
			if err != nil {
				continue
			}
			var lease LeaseV6
			if err := json.Unmarshal(data, &lease); err != nil {
				continue
			}
			unapplyLeaseV6(iface, &lease)
			_ = os.Remove(filepath.Join(pidDir, name))
		}
	}
}

func statusNative(iface string) string {
	nativeClientsMu.Lock()
	nc, okV4 := nativeClients[iface]
	ncV6, okV6 := nativeClients[iface+":6"]
	nativeClientsMu.Unlock()

	var parts []string

	if okV4 {
		nc.mu.Lock()
		if nc.lease != nil {
			parts = append(parts, fmt.Sprintf("v4=%s", nc.lease.CIDR()))
		}
		nc.mu.Unlock()
	}

	if okV6 {
		ncV6.mu.Lock()
		if ncV6.leaseV6 != nil && len(ncV6.leaseV6.Addresses) > 0 {
			parts = append(parts, fmt.Sprintf("v6=%s", ncV6.leaseV6.Addresses[0].IP))
		}
		ncV6.mu.Unlock()
	}

	if len(parts) == 0 {
		return ""
	}
	return "native dhcp " + strings.Join(parts, " ")
}
