//go:build ebpf && linux

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/SkyAPM/ktm-ebpf/iomonitor/ebpf/generated"
	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const commBanyand = "banyand"

func TestVerifierLoad(t *testing.T) {
	requireRoot(t)
	bumpMemlock(t)

	var objs generated.IomonitorObjects
	if err := generated.LoadIomonitorObjects(&objs, nil); err != nil {
		t.Fatalf("load iomonitor objects: %v", err)
	}
	defer objs.Close()
}

func TestTracepointAttach(t *testing.T) {
	requireRoot(t)
	bumpMemlock(t)

	var objs generated.IomonitorObjects
	if err := generated.LoadIomonitorObjects(&objs, nil); err != nil {
		t.Fatalf("load iomonitor objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TraceEnterReadTp, nil)
	if err != nil {
		t.Fatalf("attach tracepoint syscalls/sys_enter_read: %v", err)
	}
	defer tp.Close()
}

func TestCgroupFilter(t *testing.T) {
	requireRoot(t)
	bumpMemlock(t)

	cgMount, err := cgroup2Mount()
	if err != nil {
		t.Skipf("cgroup v2 not available: %v", err)
	}

	origCgroup, err := currentCgroupPath(cgMount)
	if err != nil {
		t.Fatalf("resolve current cgroup: %v", err)
	}

	targetCgroup, err := os.MkdirTemp(origCgroup, "ktm-ebpf-target-")
	if err != nil {
		t.Fatalf("create target cgroup: %v", err)
	}
	otherCgroup, err := os.MkdirTemp(origCgroup, "ktm-ebpf-other-")
	if err != nil {
		_ = os.Remove(targetCgroup)
		t.Fatalf("create other cgroup: %v", err)
	}
	defer func() {
		_ = moveToCgroup(origCgroup)
		_ = os.Remove(otherCgroup)
		_ = os.Remove(targetCgroup)
	}()

	var objs generated.IomonitorObjects
	if err := generated.LoadIomonitorObjects(&objs, nil); err != nil {
		t.Fatalf("load iomonitor objects: %v", err)
	}
	defer objs.Close()

	enterTP, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TraceEnterReadTp, nil)
	if err != nil {
		t.Fatalf("attach tracepoint syscalls/sys_enter_read: %v", err)
	}
	defer enterTP.Close()

	exitTP, err := link.Tracepoint("syscalls", "sys_exit_read", objs.TraceExitReadTp, nil)
	if err != nil {
		t.Fatalf("attach tracepoint syscalls/sys_exit_read: %v", err)
	}
	defer exitTP.Close()

	targetID, err := cgroupInode(targetCgroup)
	if err != nil {
		t.Fatalf("stat target cgroup: %v", err)
	}
	key := uint32(0)
	if err := objs.ConfigMap.Put(key, targetID); err != nil {
		t.Fatalf("set config cgroup id: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := setComm(commBanyand); err != nil {
		t.Fatalf("set comm: %v", err)
	}

	pid := uint32(os.Getpid())
	if err := moveToCgroup(targetCgroup); err != nil {
		t.Fatalf("move to target cgroup: %v", err)
	}
	if err := triggerRead(); err != nil {
		t.Fatalf("trigger read in target cgroup: %v", err)
	}
	count := waitForReadCount(t, objs.ReadLatencyStatsMap, pid, 1)
	if count == 0 {
		t.Fatalf("expected read stats to increase in target cgroup")
	}

	if err := moveToCgroup(otherCgroup); err != nil {
		t.Fatalf("move to other cgroup: %v", err)
	}
	if err := triggerRead(); err != nil {
		t.Fatalf("trigger read in other cgroup: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	after := readLatencyCount(t, objs.ReadLatencyStatsMap, pid)
	if after != count {
		t.Fatalf("read stats changed outside target cgroup: before=%d after=%d", count, after)
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
}

func bumpMemlock(t *testing.T) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
}

func cgroup2Mount() (string, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			if _, err := os.Stat(filepath.Join(fields[1], "cgroup.controllers")); err == nil {
				return fields[1], nil
			}
		}
	}
	return "", errors.New("cgroup2 mount not found")
}

func currentCgroupPath(mount string) (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] != "0" {
			continue
		}
		cgPath := parts[2]
		if cgPath == "" {
			cgPath = "/"
		}
		if !strings.HasPrefix(cgPath, "/") {
			cgPath = "/" + cgPath
		}
		rel := strings.TrimPrefix(cgPath, "/")
		full := filepath.Clean(filepath.Join(mount, rel))
		if _, err := os.Stat(filepath.Join(full, "cgroup.procs")); err != nil {
			return "", err
		}
		return full, nil
	}
	return "", errors.New("cgroup v2 path not found in /proc/self/cgroup")
}

func cgroupInode(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

func moveToCgroup(path string) error {
	procs := filepath.Join(path, "cgroup.procs")
	pid := strconv.Itoa(os.Getpid())
	return os.WriteFile(procs, []byte(pid+"\n"), 0)
}

func setComm(name string) error {
	var buf [16]byte
	if len(name) > 15 {
		name = name[:15]
	}
	copy(buf[:], name)
	return unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&buf[0])), 0, 0, 0)
}

func triggerRead() error {
	f, err := os.Open("/proc/self/stat")
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 64)
	_, err = f.Read(buf)
	return err
}

func waitForReadCount(t *testing.T, m *ciliumebpf.Map, pid uint32, min uint64) uint64 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var count uint64
	for time.Now().Before(deadline) {
		count = readLatencyCount(t, m, pid)
		if count >= min {
			return count
		}
		time.Sleep(10 * time.Millisecond)
	}
	return count
}

func readLatencyCount(t *testing.T, m *ciliumebpf.Map, pid uint32) uint64 {
	t.Helper()
	values := make([]generated.IomonitorReadLatencyStatsT, ciliumebpf.MustPossibleCPU())
	if err := m.Lookup(&pid, &values); err != nil {
		if errors.Is(err, ciliumebpf.ErrKeyNotExist) {
			return 0
		}
		t.Fatalf("lookup read latency stats: %v", err)
	}
	var total uint64
	for _, v := range values {
		total += v.Count
	}
	return total
}
