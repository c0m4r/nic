package dns

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/c0m4r/nic/internal/executor"
)

var (
	resolvConf = "/etc/resolv.conf"

	resolverMu sync.Mutex
	managed    = managedResolver{leases: make(map[string][]string)}
)

// managedResolver tracks resolver inputs owned by this nic process. DHCP
// clients renew concurrently, so they update one shared desired state instead
// of each rewriting resolv.conf from its own lease.
type managedResolver struct {
	static []string
	leases map[string][]string
	active bool
}

// ManagedState is an opaque copy of the resolver policy owned by the current
// nic process. It is separate from Snapshot, which represents the resolver
// state nic found on the machine and restores during rollback.
type ManagedState struct {
	resolver managedResolver
}

type Snapshot struct {
	Captured  bool        `json:"captured"`
	Exists    bool        `json:"exists"`
	Content   []byte      `json:"content,omitempty"`
	Mode      os.FileMode `json:"mode,omitempty"`
	Immutable bool        `json:"immutable,omitempty"`
}

// WriteResolvConf writes nameservers to /etc/resolv.conf. It remains available
// for direct callers such as state restoration; normal configuration and DHCP
// updates should use SetStaticNameservers and SetLeaseNameservers instead.
func WriteResolvConf(nameservers []string) error {
	normalized, err := normalizeNameservers(nameservers)
	if err != nil {
		return err
	}
	if len(normalized) == 0 {
		return nil
	}
	resolverMu.Lock()
	defer resolverMu.Unlock()
	return writeResolvConfLocked(normalized)
}

// SetStaticNameservers sets the static resolver inputs from the active
// configuration. Static entries intentionally take precedence over DHCP, as
// they did before DHCP lease renewal support was added.
func SetStaticNameservers(nameservers []string) error {
	if err := ConfigureStaticNameservers(nameservers); err != nil {
		return err
	}
	return ApplyManagedNameservers()
}

// ConfigureStaticNameservers records static resolver policy without writing
// it yet. Configuration applies this before starting DHCP so native lease
// updates see the policy, then calls ApplyManagedNameservers after external
// clients have completed their initial setup.
func ConfigureStaticNameservers(nameservers []string) error {
	normalized, err := normalizeNameservers(nameservers)
	if err != nil {
		return err
	}

	resolverMu.Lock()
	defer resolverMu.Unlock()
	managed.static = normalized
	return nil
}

// ApplyManagedNameservers writes the current static and DHCP resolver inputs.
func ApplyManagedNameservers() error {
	resolverMu.Lock()
	defer resolverMu.Unlock()

	desired := managedNameservers(managed.static, managed.leases)
	if err := writeManagedResolvConfLocked(desired, managed.active || len(desired) > 0); err != nil {
		return err
	}
	managed.active = managed.active || len(desired) > 0
	return nil
}

// SetLeaseNameservers replaces the resolver inputs supplied by one DHCP
// session. source must be stable for the lifetime of that session, for example
// "dhcp4:eth0" or "dhcp6:eth0".
func SetLeaseNameservers(source string, nameservers []string) error {
	if strings.TrimSpace(source) == "" {
		return fmt.Errorf("DNS lease source is empty")
	}
	normalized, err := normalizeNameservers(nameservers)
	if err != nil {
		return err
	}

	resolverMu.Lock()
	defer resolverMu.Unlock()

	leases := cloneLeaseNameservers(managed.leases)
	if len(normalized) == 0 {
		delete(leases, source)
	} else {
		leases[source] = normalized
	}
	desired := managedNameservers(managed.static, leases)
	if err := writeManagedResolvConfLocked(desired, managed.active || len(desired) > 0); err != nil {
		return err
	}
	managed.leases = leases
	managed.active = managed.active || len(desired) > 0
	return nil
}

// RemoveLeaseNameservers removes a DHCP session's resolver inputs.
func RemoveLeaseNameservers(source string) error {
	return SetLeaseNameservers(source, nil)
}

// ResetManagedNameservers forgets in-memory resolver inputs without touching
// resolv.conf. Call it after restoring a captured resolver baseline.
func ResetManagedNameservers() {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	resetManagedLocked()
}

// CaptureManagedState preserves the active configuration and all DHCP lease
// contributions across a machine-state restore.
func CaptureManagedState() ManagedState {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	return ManagedState{resolver: cloneManagedResolver(managed)}
}

// RestoreManagedState restores and reapplies a previously captured resolver
// policy. Committing the in-memory state only after the file write succeeds
// keeps the manager consistent with resolv.conf on errors.
func RestoreManagedState(snapshot ManagedState) error {
	resolverMu.Lock()
	defer resolverMu.Unlock()

	restored := cloneManagedResolver(snapshot.resolver)
	desired := managedNameservers(restored.static, restored.leases)
	if err := writeManagedResolvConfLocked(desired, restored.active || len(desired) > 0); err != nil {
		return err
	}
	managed = restored
	return nil
}

func writeManagedResolvConfLocked(nameservers []string, shouldWrite bool) error {
	if !shouldWrite {
		return nil
	}
	if err := writeResolvConfLocked(nameservers); err != nil {
		return err
	}
	// Immutable protection is optional (and unavailable on several supported
	// filesystems), so retain the historical best-effort behavior.
	_ = guardLocked()
	return nil
}

func writeResolvConfLocked(nameservers []string) error {
	if executor.DryRun {
		fmt.Printf("[dry-run] write %s with nameservers: %s\n",
			resolvConf, strings.Join(nameservers, ", "))
		return nil
	}

	// Validate before removing immutable protection so bad input cannot leave a
	// previously protected resolver writable.
	for _, ns := range nameservers {
		if net.ParseIP(ns) == nil {
			return fmt.Errorf("invalid nameserver %q", ns)
		}
	}
	if err := unguardLocked(); err != nil {
		return fmt.Errorf("unguard %s: %w", resolvConf, err)
	}

	var sb strings.Builder
	sb.WriteString("# Generated by nic - do not edit\n")
	for _, ns := range nameservers {
		sb.WriteString("nameserver ")
		sb.WriteString(ns)
		sb.WriteByte('\n')
	}

	if err := os.WriteFile(resolvConf, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("write %s: %w", resolvConf, err)
	}

	return nil
}

func normalizeNameservers(nameservers []string) ([]string, error) {
	result := make([]string, 0, len(nameservers))
	seen := make(map[string]bool, len(nameservers))
	for _, ns := range nameservers {
		parsed := net.ParseIP(strings.TrimSpace(ns))
		if parsed == nil {
			return nil, fmt.Errorf("invalid nameserver %q", ns)
		}
		canonical := parsed.String()
		if !seen[canonical] {
			seen[canonical] = true
			result = append(result, canonical)
		}
	}
	return result, nil
}

func cloneLeaseNameservers(leases map[string][]string) map[string][]string {
	cloned := make(map[string][]string, len(leases))
	for source, nameservers := range leases {
		cloned[source] = append([]string(nil), nameservers...)
	}
	return cloned
}

func cloneManagedResolver(source managedResolver) managedResolver {
	return managedResolver{
		static: append([]string(nil), source.static...),
		leases: cloneLeaseNameservers(source.leases),
		active: source.active,
	}
}

func managedNameservers(static []string, leases map[string][]string) []string {
	if len(static) > 0 {
		return append([]string(nil), static...)
	}

	sources := make([]string, 0, len(leases))
	for source := range leases {
		sources = append(sources, source)
	}
	sort.Strings(sources)

	result := make([]string, 0)
	seen := make(map[string]bool)
	for _, source := range sources {
		for _, ns := range leases[source] {
			if !seen[ns] {
				seen[ns] = true
				result = append(result, ns)
			}
		}
	}
	return result
}

func resetManagedLocked() {
	managed = managedResolver{leases: make(map[string][]string)}
}

// Capture records the resolver contents and protection state for rollback.
func Capture() (Snapshot, error) {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	return captureLocked()
}

func captureLocked() (Snapshot, error) {
	info, err := os.Stat(resolvConf)
	if errorsIsNotExist(err) {
		return Snapshot{Captured: true}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	content, err := os.ReadFile(resolvConf)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{Captured: true, Exists: true, Content: content, Mode: info.Mode().Perm()}
	if executor.CommandExists("lsattr") {
		fields := strings.Fields(executor.RunSilent("lsattr", "-d", resolvConf))
		if len(fields) > 0 && strings.Contains(fields[0], "i") {
			snapshot.Immutable = true
		}
	}
	return snapshot, nil
}

// Restore puts back the resolver state captured before nic made changes.
func Restore(snapshot Snapshot) error {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	return restoreLocked(snapshot)
}

func restoreLocked(snapshot Snapshot) error {
	if !snapshot.Captured {
		return nil
	}
	if executor.DryRun {
		fmt.Printf("[dry-run] restore %s\n", resolvConf)
		resetManagedLocked()
		return nil
	}
	if err := unguardLocked(); err != nil {
		return err
	}
	if !snapshot.Exists {
		if err := os.Remove(resolvConf); err != nil && !errorsIsNotExist(err) {
			return err
		}
		resetManagedLocked()
		return nil
	}
	if err := os.WriteFile(resolvConf, snapshot.Content, snapshot.Mode); err != nil {
		return fmt.Errorf("restore %s: %w", resolvConf, err)
	}
	if err := os.Chmod(resolvConf, snapshot.Mode); err != nil {
		return fmt.Errorf("restore mode for %s: %w", resolvConf, err)
	}
	resetManagedLocked()
	if snapshot.Immutable {
		if err := guardLocked(); err != nil {
			return fmt.Errorf("restore immutable flag: %w", err)
		}
	}
	return nil
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}

// Guard makes /etc/resolv.conf immutable to prevent other tools from modifying it.
func Guard() error {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	return guardLocked()
}

func guardLocked() error {
	if executor.DryRun {
		fmt.Printf("[dry-run] chattr +i %s\n", resolvConf)
		return nil
	}
	if !executor.CommandExists("chattr") {
		return nil // Silently skip if chattr not available
	}
	_, err := executor.Run("chattr", "+i", resolvConf)
	return err
}

// Unguard removes the immutable flag from /etc/resolv.conf.
func Unguard() error {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	return unguardLocked()
}

func unguardLocked() error {
	if !executor.CommandExists("chattr") {
		return nil
	}
	_, err := executor.Run("chattr", "-i", resolvConf)
	if err != nil {
		message := strings.ToLower(err.Error())
		for _, benign := range []string{"operation not supported", "inappropriate ioctl", "not supported"} {
			if strings.Contains(message, benign) {
				return nil
			}
		}
	}
	return err
}

// CurrentNameservers reads current nameservers from /etc/resolv.conf.
func CurrentNameservers() []string {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	return currentNameserversLocked()
}

func currentNameserversLocked() []string {
	f, err := os.Open(resolvConf)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver ") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
			if ns != "" {
				servers = append(servers, ns)
			}
		}
	}
	return servers
}
