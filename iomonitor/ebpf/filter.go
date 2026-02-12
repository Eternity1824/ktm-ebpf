//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrProcessNotFound is returned when no process with the given comm name is found.
var ErrProcessNotFound = errors.New("process not found")

// resolveTargetCgroupPath returns the absolute cgroup v2 directory path to use
// as the eBPF cgroup filter target.
//
// If cfgPath is non-empty it is used directly (after validation).
// Otherwise the function locates the banyand process via /proc and returns its
// container-level cgroup path so that bpf_get_current_cgroup_id() in the
// kernel will produce an exact match.
func resolveTargetCgroupPath(cfgPath string) (string, error) {
	if cfgPath != "" {
		return resolveCgroupPath(cfgPath)
	}

	// Find the banyand process and use its container-level cgroup.
	targetPID, findErr := findPIDByComm("banyand")
	if findErr != nil {
		return "", fmt.Errorf("failed to find banyand process: %w", findErr)
	}

	cgRel, readErr := readCgroupV2Path(targetPID)
	if readErr != nil {
		return "", fmt.Errorf("failed to read cgroup for banyand (pid %d): %w", targetPID, readErr)
	}

	cgMount, mountErr := findCgroup2Mount()
	if mountErr != nil {
		return "", fmt.Errorf("failed to find cgroup2 mount: %w", mountErr)
	}

	return filepath.Join(cgMount, cgRel), nil
}

// resolveCgroupPath validates that the given path exists and looks like a
// cgroup v2 directory (contains cgroup.procs).
func resolveCgroupPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(abs, "cgroup.procs")); err != nil {
		return "", fmt.Errorf("not a valid cgroup directory: %w", err)
	}
	return abs, nil
}

// findPIDByComm scans /proc to find the first process whose comm matches name.
func findPIDByComm(name string) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue // process may have exited
		}
		if strings.TrimSpace(string(comm)) == name {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("%w: comm=%q", ErrProcessNotFound, name)
}

// readCgroupV2Path reads /proc/<pid>/cgroup and returns the cgroup v2
// relative path (the part after "0::").
func readCgroupV2Path(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// cgroup v2 lines look like "0::/path/to/cgroup"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" {
			continue
		}
		cgPath := parts[2]
		if cgPath == "" {
			cgPath = "/"
		}
		return cgPath, nil
	}
	return "", fmt.Errorf("cgroup v2 entry not found in /proc/%d/cgroup", pid)
}

// cgroupID returns the inode number (used as cgroup ID by the kernel) for the
// given cgroup directory path.
func cgroupID(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// findCgroup2Mount locates the cgroup v2 unified mount point.
func findCgroup2Mount() (string, error) {
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
