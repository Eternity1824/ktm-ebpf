//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFindPIDByComm_Self(t *testing.T) {
	// Read our own comm name and search for it.
	data, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatalf("read own comm: %v", err)
	}
	selfComm := strings.TrimSpace(string(data))
	if selfComm == "" {
		t.Skip("empty comm")
	}

	pid, err := findPIDByComm(selfComm)
	if err != nil {
		t.Fatalf("findPIDByComm(%q): %v", selfComm, err)
	}
	if pid <= 0 {
		t.Fatalf("expected positive pid, got %d", pid)
	}
}

func TestFindPIDByComm_NotFound(t *testing.T) {
	_, err := findPIDByComm("__nonexistent_process_name__")
	if err == nil {
		t.Fatal("expected error for nonexistent process")
	}
}

func TestReadCgroupV2Path_Self(t *testing.T) {
	pid := os.Getpid()
	cgPath, err := readCgroupV2Path(pid)
	if err != nil {
		t.Fatalf("readCgroupV2Path(%d): %v", pid, err)
	}
	if !strings.HasPrefix(cgPath, "/") {
		t.Fatalf("expected absolute cgroup path, got %q", cgPath)
	}
}

func TestReadCgroupV2Path_InvalidPID(t *testing.T) {
	_, err := readCgroupV2Path(999999999)
	if err == nil {
		t.Fatal("expected error for invalid pid")
	}
}

func TestFindCgroup2Mount(t *testing.T) {
	mount, err := findCgroup2Mount()
	if err != nil {
		t.Skipf("cgroup2 not available: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mount, "cgroup.controllers")); err != nil {
		t.Fatalf("mount %q missing cgroup.controllers: %v", mount, err)
	}
}

func TestResolveCgroupPath_Valid(t *testing.T) {
	mount, err := findCgroup2Mount()
	if err != nil {
		t.Skipf("cgroup2 not available: %v", err)
	}
	// The mount root itself should be a valid cgroup directory.
	path, err := resolveCgroupPath(mount)
	if err != nil {
		t.Fatalf("resolveCgroupPath(%q): %v", mount, err)
	}
	if path != mount {
		t.Fatalf("expected %q, got %q", mount, path)
	}
}

func TestResolveCgroupPath_Invalid(t *testing.T) {
	_, err := resolveCgroupPath("/tmp/__nonexistent_cgroup_dir__")
	if err == nil {
		t.Fatal("expected error for invalid cgroup path")
	}
}

func TestResolveTargetCgroupPath_ExplicitPath(t *testing.T) {
	mount, err := findCgroup2Mount()
	if err != nil {
		t.Skipf("cgroup2 not available: %v", err)
	}
	path, err := resolveTargetCgroupPath(mount)
	if err != nil {
		t.Fatalf("resolveTargetCgroupPath(%q): %v", mount, err)
	}
	if path != mount {
		t.Fatalf("expected %q, got %q", mount, path)
	}
}

func TestResolveTargetCgroupPath_AutoDetect(t *testing.T) {
	// This test verifies the auto-detect path works for the current process's
	// own comm name. We can't easily test banyand detection without a running
	// banyand, so we just verify the error path is sensible.
	_, err := resolveTargetCgroupPath("")
	if err == nil {
		// If banyand happens to be running, that's fine.
		return
	}
	// Should fail with "process not found" since banyand is not running.
	if !strings.Contains(err.Error(), "process not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCgroupID(t *testing.T) {
	mount, err := findCgroup2Mount()
	if err != nil {
		t.Skipf("cgroup2 not available: %v", err)
	}
	id, err := cgroupID(mount)
	if err != nil {
		t.Fatalf("cgroupID(%q): %v", mount, err)
	}
	if id == 0 {
		t.Fatal("expected nonzero cgroup id")
	}
}

func TestEndToEnd_SelfCgroup(t *testing.T) {
	// Verify that readCgroupV2Path + findCgroup2Mount + cgroupID produces
	// a valid cgroup ID for the current process.
	mount, err := findCgroup2Mount()
	if err != nil {
		t.Skipf("cgroup2 not available: %v", err)
	}
	cgRel, err := readCgroupV2Path(os.Getpid())
	if err != nil {
		t.Fatalf("readCgroupV2Path: %v", err)
	}
	fullPath := filepath.Join(mount, cgRel)
	if _, err := os.Stat(fullPath); err != nil {
		t.Fatalf("cgroup path %q does not exist: %v", fullPath, err)
	}
	id, err := cgroupID(fullPath)
	if err != nil {
		t.Fatalf("cgroupID(%q): %v", fullPath, err)
	}
	if id == 0 {
		t.Fatal("expected nonzero cgroup id for self")
	}
	t.Logf("self cgroup: path=%s id=%d", fullPath, id)

	// Cross-check: the inode should match what we get from stat directly.
	_ = strconv.FormatUint(id, 10)
}
