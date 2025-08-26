// SPDX-FileCopyrightText: Copyright The Lima Authors
// SPDX-License-Identifier: Apache-2.0

package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/luthermonson/go-proxmox"
	"github.com/docker/go-units"
	"github.com/mattn/go-shellwords"
	"github.com/sirupsen/logrus"

	"github.com/lima-vm/lima/v2/pkg/fileutils"
	"github.com/lima-vm/lima/v2/pkg/iso9660util"
	"github.com/lima-vm/lima/v2/pkg/limayaml"
	"github.com/lima-vm/lima/v2/pkg/networks"
	"github.com/lima-vm/lima/v2/pkg/networks/usernet"
	"github.com/lima-vm/lima/v2/pkg/qemuimgutil"
	"github.com/lima-vm/lima/v2/pkg/store"
	"github.com/lima-vm/lima/v2/pkg/store/filenames"
)

type Config struct {
	Name         string
	InstanceDir  string
	LimaYAML     *limayaml.LimaYAML
	SSHLocalPort int
	SSHAddress   string

	Client       *proxmox.Client
}

// EnsureDisk ensures the basedisk and diffdisk.
func EnsureDisk(_ context.Context, cfg Config) error {
	diffDisk := filepath.Join(cfg.InstanceDir, filenames.DiffDisk)
	if _, err := os.Stat(diffDisk); err == nil || !errors.Is(err, os.ErrNotExist) {
		// disk is already ensured
		return err
	}

	baseDisk := filepath.Join(cfg.InstanceDir, filenames.BaseDisk)

	diskSize, _ := units.RAMInBytes(*cfg.LimaYAML.Disk)
	if diskSize == 0 {
		return nil
	}
	isBaseDiskISO, err := iso9660util.IsISO9660(baseDisk)
	if err != nil {
		return err
	}
	baseDiskInfo, err := qemuimgutil.GetInfo(baseDisk)
	if err != nil {
		return fmt.Errorf("failed to get the information of base disk %q: %w", baseDisk, err)
	}
	if err = qemuimgutil.AcceptableAsBaseDisk(baseDiskInfo); err != nil {
		return fmt.Errorf("file %q is not acceptable as the base disk: %w", baseDisk, err)
	}
	if baseDiskInfo.Format == "" {
		return fmt.Errorf("failed to inspect the format of %q", baseDisk)
	}
	args := []string{"create", "-f", "qcow2"}
	if !isBaseDiskISO {
		args = append(args, "-F", baseDiskInfo.Format, "-b", baseDisk)
	}
	args = append(args, diffDisk, strconv.Itoa(int(diskSize)))
	cmd := exec.Command("qemu-img", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to run %v: %q: %w", cmd.Args, string(out), err)
	}
	return nil
}

func argValue(args []string, key string) (string, bool) {
	if !strings.HasPrefix(key, "-") {
		panic(fmt.Errorf("got unexpected key %q", key))
	}
	for i, s := range args {
		if s == key {
			if i == len(args)-1 {
				return "", true
			}
			value := args[i+1]
			if strings.HasPrefix(value, "-") {
				return "", true
			}
			return value, true
		}
	}
	return "", false
}

// appendArgsIfNoConflict can be used for: -cpu, -machine, -m, -boot ...
// appendArgsIfNoConflict cannot be used for: -drive, -cdrom, ...
func appendArgsIfNoConflict(args []string, k, v string) []string {
	if !strings.HasPrefix(k, "-") {
		panic(fmt.Errorf("got unexpected key %q", k))
	}
	switch k {
	case "-drive", "-cdrom", "-chardev", "-blockdev", "-netdev", "-device":
		panic(fmt.Errorf("appendArgsIfNoConflict() must not be called with k=%q", k))
	}

	if v == "" {
		if _, ok := argValue(args, k); ok {
			return args
		}
		return append(args, k)
	}

	if origV, ok := argValue(args, k); ok {
		logrus.Warnf("Not adding QEMU argument %q %q, as it conflicts with %q %q", k, v, k, origV)
		return args
	}
	return append(args, k, v)
}

type features struct {
	// AccelHelp is the output of `qemu-system-x86_64 -accel help`
	// e.g. "Accelerators supported in QEMU binary:\ntcg\nhax\nhvf\n"
	// Not machine-readable, but checking strings.Contains() should be fine.
	AccelHelp []byte
	// NetdevHelp is the output of `qemu-system-x86_64 -netdev help`
	// e.g. "Available netdev backend types:\nsocket\nhubport\ntap\nuser\nvde\nbridge\vhost-user\n"
	// Not machine-readable, but checking strings.Contains() should be fine.
	NetdevHelp []byte
	// MachineHelp is the output of `qemu-system-x86_64 -machine help`
	// e.g. "Supported machines are:\nakita...\n...virt-6.2...\n...virt-7.0...\n...\n"
	// Not machine-readable, but checking strings.Contains() should be fine.
	MachineHelp []byte
	// CPUHelp is the output of `qemu-system-x86_64 -cpu help`
	// e.g. "Available CPUs:\n...\nx86 base...\nx86 host...\n...\n"
	// Not machine-readable, but checking strings.Contains() should be fine.
	CPUHelp []byte
}

func inspectFeatures(exe, machine string) (*features, error) {
	var (
		f      features
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	cmd := exec.Command(exe, "-M", "none", "-accel", "help")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run %v: stdout=%q, stderr=%q", cmd.Args, stdout.String(), stderr.String())
	}
	f.AccelHelp = stdout.Bytes()
	// on older versions qemu will write "help" output to stderr
	if len(f.AccelHelp) == 0 {
		f.AccelHelp = stderr.Bytes()
	}

	cmd = exec.Command(exe, "-M", "none", "-netdev", "help")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		logrus.Warnf("failed to run %v: stdout=%q, stderr=%q", cmd.Args, stdout.String(), stderr.String())
	} else {
		f.NetdevHelp = stdout.Bytes()
		if len(f.NetdevHelp) == 0 {
			f.NetdevHelp = stderr.Bytes()
		}
	}

	cmd = exec.Command(exe, "-machine", "help")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		logrus.Warnf("failed to run %v: stdout=%q, stderr=%q", cmd.Args, stdout.String(), stderr.String())
	} else {
		f.MachineHelp = stdout.Bytes()
		if len(f.MachineHelp) == 0 {
			f.MachineHelp = stderr.Bytes()
		}
	}

	// Avoid error: "No machine specified, and there is no default"
	cmd = exec.Command(exe, "-cpu", "help", "-machine", machine)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		logrus.Warnf("failed to run %v: stdout=%q, stderr=%q", cmd.Args, stdout.String(), stderr.String())
	} else {
		f.CPUHelp = stdout.Bytes()
		if len(f.CPUHelp) == 0 {
			f.CPUHelp = stderr.Bytes()
		}
	}

	return &f, nil
}

// qemuMachine returns string to use for -machine.
func qemuMachine(arch limayaml.Arch) string {
	if arch == limayaml.X8664 {
		return "q35"
	}
	return "virt"
}

// audioDevice returns the default audio device.
func audioDevice() string {
	switch runtime.GOOS {
	case "darwin":
		return "coreaudio"
	case "linux":
		return "pa" // pulseaudio
	case "windows":
		return "dsound"
	}
	return "oss"
}

func defaultCPUType() limayaml.CPUType {
	// x86_64 + TCG + max was previously unstable until 2021.
	// https://bugzilla.redhat.com/show_bug.cgi?id=1999700
	// https://bugs.launchpad.net/qemu/+bug/1748296
	defaultX8664 := "max"
	if runtime.GOOS == "windows" && runtime.GOARCH == "amd64" {
		// https://github.com/lima-vm/lima/pull/3487#issuecomment-2846253560
		// > #931 intentionally prevented the code from setting it to max when running on Windows,
		// > and kept it at qemu64.
		//
		// TODO: remove this if "max" works with the latest qemu
		defaultX8664 = "qemu64"
	}
	cpuType := map[limayaml.Arch]string{
		limayaml.AARCH64: "max",
		limayaml.ARMV7L:  "max",
		limayaml.X8664:   defaultX8664,
		limayaml.PPC64LE: "max",
		limayaml.RISCV64: "max",
		limayaml.S390X:   "max",
	}
	for arch := range cpuType {
		if limayaml.IsNativeArch(arch) && limayaml.IsAccelOS() {
			if limayaml.HasHostCPU() {
				cpuType[arch] = "host"
			}
		}
		if arch == limayaml.X8664 && runtime.GOOS == "darwin" {
			// disable AVX-512, since it requires trapping instruction faults in guest
			// Enterprise Linux requires either v2 (SSE4) or v3 (AVX2), but not yet v4.
			cpuType[arch] += ",-avx512vl"

			// Disable pdpe1gb on Intel Mac
			// https://github.com/lima-vm/lima/issues/1485
			// https://stackoverflow.com/a/72863744/5167443
			cpuType[arch] += ",-pdpe1gb"
		}
	}
	return cpuType
}

func resolveCPUType(y *limayaml.LimaYAML) string {
	cpuType := defaultCPUType()
	var overrideCPUType bool
	for k, v := range y.VMOpts.QEMU.CPUType {
		if !slices.Contains(limayaml.ArchTypes, *y.Arch) {
			logrus.Warnf("field `vmOpts.qemu.cpuType` uses unsupported arch %q", k)
			continue
		}
		if v != "" {
			overrideCPUType = true
			cpuType[k] = v
		}
	}
	if overrideCPUType {
		y.VMOpts.QEMU.CPUType = cpuType
	}

	return cpuType[*y.Arch]
}

func Cmdline(ctx context.Context, cfg Config) (exe string, args []string, err error) {
	y := cfg.LimaYAML
	exe, args, err = Exe(*y.Arch)
	if err != nil {
		return "", nil, err
	}

	features, err := inspectFeatures(exe, qemuMachine(*y.Arch))
	if err != nil {
		return "", nil, err
	}

	// Architecture
	accel := Accel(*y.Arch)
	if !strings.Contains(string(features.AccelHelp), accel) {
		return "", nil, fmt.Errorf("accelerator %q is not supported by %s", accel, exe)
	}

	// Memory
	memBytes, err := units.RAMInBytes(*y.Memory)
	if err != nil {
		return "", nil, err
	}
	args = appendArgsIfNoConflict(args, "-m", strconv.Itoa(int(memBytes>>20)))

	if *y.MountType == limayaml.VIRTIOFS {
		args = appendArgsIfNoConflict(args, "-object",
			fmt.Sprintf("memory-backend-file,id=virtiofs-shm,size=%s,mem-path=/dev/shm,share=on", strconv.Itoa(int(memBytes))))
		args = appendArgsIfNoConflict(args, "-numa", "node,memdev=virtiofs-shm")
	}

	// CPU
	cpu := resolveCPUType(y)
	args = appendArgsIfNoConflict(args, "-cpu", cpu)

	// Machine
	switch *y.Arch {
	case limayaml.X8664:
		switch accel {
		case "tcg":
			// use q35 machine with vmware io port disabled.
			args = appendArgsIfNoConflict(args, "-machine", "q35,vmport=off")
			// use tcg accelerator with multi threading with 512MB translation block size
			// https://qemu-project.gitlab.io/qemu/devel/multi-thread-tcg.html?highlight=tcg
			// https://qemu-project.gitlab.io/qemu/system/invocation.html?highlight=tcg%20opts
			// this will make sure each vCPU will be backed by 1 host user thread.
			args = appendArgsIfNoConflict(args, "-accel", "tcg,thread=multi,tb-size=512")
			// This will disable CPU S3/S4 state.
			args = append(args, "-global", "ICH9-LPC.disable_s3=1")
			args = append(args, "-global", "ICH9-LPC.disable_s4=1")
		case "whpx":
			// whpx: injection failed, MSI (0, 0) delivery: 0, dest_mode: 0, trigger mode: 0, vector: 0
			args = appendArgsIfNoConflict(args, "-machine", "q35,accel="+accel+",kernel-irqchip=off")
		default:
			args = appendArgsIfNoConflict(args, "-machine", "q35,accel="+accel)
		}
	case limayaml.AARCH64:
		machine := "virt,accel=" + accel
		args = appendArgsIfNoConflict(args, "-machine", machine)
	case limayaml.RISCV64:
		machine := "virt,acpi=off,accel=" + accel
		args = appendArgsIfNoConflict(args, "-machine", machine)
	case limayaml.ARMV7L:
		machine := "virt,accel=" + accel
		args = appendArgsIfNoConflict(args, "-machine", machine)
	}

	// SMP
	args = appendArgsIfNoConflict(args, "-smp",
		fmt.Sprintf("%d,sockets=1,cores=%d,threads=1", *y.CPUs, *y.CPUs))

	// Firmware
	legacyBIOS := *y.Firmware.LegacyBIOS
	if legacyBIOS && *y.Arch != limayaml.X8664 && *y.Arch != limayaml.ARMV7L {
		logrus.Warnf("field `firmware.legacyBIOS` is not supported for architecture %q, ignoring", *y.Arch)
		legacyBIOS = false
	}
	noFirmware := *y.Arch == limayaml.PPC64LE || *y.Arch == limayaml.S390X || legacyBIOS
	if !noFirmware {
		var firmware string
		firmwareInBios := runtime.GOOS == "windows"
		if envVar := os.Getenv("_LIMA_QEMU_UEFI_IN_BIOS"); envVar != "" {
			b, err := strconv.ParseBool(envVar)
			if err != nil {
				logrus.WithError(err).Warnf("invalid _LIMA_QEMU_UEFI_IN_BIOS value %q", envVar)
			} else {
				firmwareInBios = b
			}
		}
		firmwareInBios = firmwareInBios && *y.Arch == limayaml.X8664
		downloadedFirmware := filepath.Join(cfg.InstanceDir, filenames.QemuEfiCodeFD)
		firmwareWithVars := filepath.Join(cfg.InstanceDir, filenames.QemuEfiFullFD)
		if firmwareInBios {
			if _, stErr := os.Stat(firmwareWithVars); stErr == nil {
				firmware = firmwareWithVars
				logrus.Infof("Using existing firmware (%q)", firmware)
			}
		} else {
			if _, stErr := os.Stat(downloadedFirmware); errors.Is(stErr, os.ErrNotExist) {
			loop:
				for _, f := range y.Firmware.Images {
					switch f.VMType {
					case "", limayaml.QEMU:
						if f.Arch == *y.Arch {
							if _, err = fileutils.DownloadFile(ctx, downloadedFirmware, f.File, true, "UEFI code "+f.Location, *y.Arch); err != nil {
								logrus.WithError(err).Warnf("failed to download %q", f.Location)
								continue loop
							}
							firmware = downloadedFirmware
							logrus.Infof("Using firmware %q (downloaded from %q)", firmware, f.Location)
							break loop
						}
					}
				}
			} else {
				firmware = downloadedFirmware
				logrus.Infof("Using existing firmware (%q)", firmware)
			}
		}
		if firmware != "" {
			if firmwareInBios {
				args = append(args, "-bios", firmware)
			} else {
				args = append(args, "-drive", fmt.Sprintf("if=pflash,format=raw,readonly=on,file=%s", firmware))
			}
		}
	}

	// Disk
	baseDisk := filepath.Join(cfg.InstanceDir, filenames.BaseDisk)
	diffDisk := filepath.Join(cfg.InstanceDir, filenames.DiffDisk)
	extraDisks := []string{}
	for _, d := range y.AdditionalDisks {
		diskName := d.Name
		disk, err := store.InspectDisk(diskName)
		if err != nil {
			logrus.Errorf("could not load disk %q: %q", diskName, err)
			return "", nil, err
		}

		if disk.Instance != "" {
			if disk.InstanceDir != cfg.InstanceDir {
				logrus.Errorf("could not attach disk %q, in use by instance %q", diskName, disk.Instance)
				return "", nil, err
			}
			err = disk.Unlock()
			if err != nil {
				logrus.Errorf("could not unlock disk %q to reuse in the same instance %q", diskName, cfg.Name)
				return "", nil, err
			}
		}
		logrus.Infof("Mounting disk %q on %q", diskName, disk.MountPoint)
		err = disk.Lock(cfg.InstanceDir)
		if err != nil {
			logrus.Errorf("could not lock disk %q: %q", diskName, err)
			return "", nil, err
		}
		dataDisk := filepath.Join(disk.Dir, filenames.DataDisk)
		extraDisks = append(extraDisks, dataDisk)
	}

	isBaseDiskCDROM, err := iso9660util.IsISO9660(baseDisk)
	if err != nil {
		return "", nil, err
	}
	if isBaseDiskCDROM {
		args = appendArgsIfNoConflict(args, "-boot", "order=d,splash-time=0,menu=on")
		args = append(args, "-drive", fmt.Sprintf("file=%s,format=raw,media=cdrom,readonly=on", baseDisk))
	} else {
		args = appendArgsIfNoConflict(args, "-boot", "order=c,splash-time=0,menu=on")
	}
	if diskSize, _ := units.RAMInBytes(*cfg.LimaYAML.Disk); diskSize > 0 {
		args = append(args, "-drive", fmt.Sprintf("file=%s,if=virtio,discard=on", diffDisk))
	} else if !isBaseDiskCDROM {
		baseDiskInfo, err := qemuimgutil.GetInfo(baseDisk)
		if err != nil {
			return "", nil, fmt.Errorf("failed to get the information of %q: %w", baseDisk, err)
		}
		if err = qemuimgutil.AcceptableAsBaseDisk(baseDiskInfo); err != nil {
			return "", nil, fmt.Errorf("file %q is not acceptable as the base disk: %w", baseDisk, err)
		}
		if baseDiskInfo.Format == "" {
			return "", nil, fmt.Errorf("failed to inspect the format of %q", baseDisk)
		}
		args = append(args, "-drive", fmt.Sprintf("file=%s,format=%s,if=virtio,discard=on", baseDisk, baseDiskInfo.Format))
	}
	for _, extraDisk := range extraDisks {
		args = append(args, "-drive", fmt.Sprintf("file=%s,if=virtio,discard=on", extraDisk))
	}

	// cloud-init
	args = append(args,
		"-drive", "id=cdrom0,if=none,format=raw,readonly=on,file="+filepath.Join(cfg.InstanceDir, filenames.CIDataISO),
		"-device", "virtio-scsi-pci,id=scsi0",
		"-device", "scsi-cd,bus=scsi0.0,drive=cdrom0")

	// Network
	// Configure default usernetwork with limayaml.MACAddress(driver.Instance.Dir) for eth0 interface
	firstUsernetIndex := limayaml.FirstUsernetIndex(y)
	if firstUsernetIndex == -1 {
		args = append(args, "-netdev", fmt.Sprintf("user,id=net0,net=%s,dhcpstart=%s,hostfwd=tcp:%s:%d-:22",
			networks.SlirpNetwork, networks.SlirpIPAddress, cfg.SSHAddress, cfg.SSHLocalPort))
	} else {
		qemuSock, err := usernet.Sock(y.Networks[firstUsernetIndex].Lima, usernet.QEMUSock)
		if err != nil {
			return "", nil, err
		}
		args = append(args, "-netdev", fmt.Sprintf("socket,id=net0,fd={{ fd_connect %q }}", qemuSock))
	}
	virtioNet := "virtio-net-pci"
	if *y.Arch == limayaml.S390X {
		// virtio-net-pci does not work on EL, while it works on Ubuntu
		// https://github.com/lima-vm/lima/pull/3319/files#r1986388345
		virtioNet = "virtio-net-ccw"
	}
	args = append(args, "-device", virtioNet+",netdev=net0,mac="+limayaml.MACAddress(cfg.InstanceDir))

	for i, nw := range y.Networks {
		if nw.Lima != "" {
			nwCfg, err := networks.LoadConfig()
			if err != nil {
				return "", nil, err
			}

			// Handle usernet connections
			isUsernet, err := nwCfg.Usernet(nw.Lima)
			if err != nil {
				return "", nil, err
			}
			if isUsernet {
				if i == firstUsernetIndex {
					continue
				}
				qemuSock, err := usernet.Sock(nw.Lima, usernet.QEMUSock)
				if err != nil {
					return "", nil, err
				}
				args = append(args, "-netdev", fmt.Sprintf("socket,id=net%d,fd={{ fd_connect %q }}", i+1, qemuSock))
				args = append(args, "-device", fmt.Sprintf("%s,netdev=net%d,mac=%s", virtioNet, i+1, nw.MACAddress))
			} else {
				if runtime.GOOS != "darwin" {
					return "", nil, fmt.Errorf("networks.yaml '%s' configuration is only supported on macOS right now", nw.Lima)
				}
				logrus.Debugf("Using socketVMNet (%q)", nwCfg.Paths.SocketVMNet)
				sock, err := networks.Sock(nw.Lima)
				if err != nil {
					return "", nil, err
				}
				args = append(args, "-netdev", fmt.Sprintf("socket,id=net%d,fd={{ fd_connect %q }}", i+1, sock))
				// TODO: should we also validate that the socket exists, or do we rely on the
				// networks reconciler to throw an error when the network cannot start?
			}
		} else if nw.Socket != "" {
			args = append(args, "-netdev", fmt.Sprintf("socket,id=net%d,fd={{ fd_connect %q }}", i+1, nw.Socket))
		} else {
			return "", nil, fmt.Errorf("invalid network spec %+v", nw)
		}
		args = append(args, "-device", fmt.Sprintf("%s,netdev=net%d,mac=%s", virtioNet, i+1, nw.MACAddress))
	}

	// virtio-rng-pci accelerates starting up the OS, according to https://wiki.gentoo.org/wiki/QEMU/Options
	args = append(args, "-device", "virtio-rng-pci")

	// Input
	input := "mouse"

	switch *y.Arch {
	// FIXME: use virtio-gpu on all the architectures
	case limayaml.X8664, limayaml.RISCV64:
		args = append(args, "-device", "virtio-vga")
	default:
		args = append(args, "-device", "virtio-gpu")
	}
	args = append(args, "-device", "virtio-keyboard-pci")
	args = append(args, "-device", "virtio-"+input+"-pci")
	args = append(args, "-device", "qemu-xhci,id=usb-bus")

	// Parallel
	args = append(args, "-parallel", "none")

	// Serial (default)
	// This is ttyS0 for Intel and RISC-V, ttyAMA0 for ARM.
	serialSock := filepath.Join(cfg.InstanceDir, filenames.SerialSock)
	if err := os.RemoveAll(serialSock); err != nil {
		return "", nil, err
	}
	serialLog := filepath.Join(cfg.InstanceDir, filenames.SerialLog)
	if err := os.RemoveAll(serialLog); err != nil {
		return "", nil, err
	}
	const serialChardev = "char-serial"
	args = append(args, "-chardev", fmt.Sprintf("socket,id=%s,path=%s,server=on,wait=off,logfile=%s", serialChardev, serialSock, serialLog))
	args = append(args, "-serial", "chardev:"+serialChardev)

	// Serial (PCI, ARM only)
	// On ARM, the default serial is ttyAMA0, this PCI serial is ttyS0.
	// https://gitlab.com/qemu-project/qemu/-/issues/1801#note_1494720586
	switch *y.Arch {
	case limayaml.AARCH64, limayaml.ARMV7L:
		serialpSock := filepath.Join(cfg.InstanceDir, filenames.SerialPCISock)
		if err := os.RemoveAll(serialpSock); err != nil {
			return "", nil, err
		}
		serialpLog := filepath.Join(cfg.InstanceDir, filenames.SerialPCILog)
		if err := os.RemoveAll(serialpLog); err != nil {
			return "", nil, err
		}
		const serialpChardev = "char-serial-pci"
		args = append(args, "-chardev", fmt.Sprintf("socket,id=%s,path=%s,server=on,wait=off,logfile=%s", serialpChardev, serialpSock, serialpLog))
		args = append(args, "-device", "pci-serial,chardev="+serialpChardev)
	}

	// Serial (virtio)
	serialvSock := filepath.Join(cfg.InstanceDir, filenames.SerialVirtioSock)
	if err := os.RemoveAll(serialvSock); err != nil {
		return "", nil, err
	}
	serialvLog := filepath.Join(cfg.InstanceDir, filenames.SerialVirtioLog)
	if err := os.RemoveAll(serialvLog); err != nil {
		return "", nil, err
	}
	const serialvChardev = "char-serial-virtio"
	args = append(args, "-chardev", fmt.Sprintf("socket,id=%s,path=%s,server=on,wait=off,logfile=%s", serialvChardev, serialvSock, serialvLog))
	// max_ports=1 is required for https://github.com/lima-vm/lima/issues/1689 https://github.com/lima-vm/lima/issues/1691
	serialvMaxPorts := 1
	if *y.Arch == limayaml.S390X {
		serialvMaxPorts++ // needed to avoid `virtio-serial-bus: Out-of-range port id specified, max. allowed: 0`
	}
	args = append(args, "-device", fmt.Sprintf("virtio-serial-pci,id=virtio-serial0,max_ports=%d", serialvMaxPorts))
	args = append(args, "-device", fmt.Sprintf("virtconsole,chardev=%s,id=console0", serialvChardev))

	// We also want to enable vsock here, but QEMU does not support vsock for macOS hosts

	if *y.MountType == limayaml.NINEP || *y.MountType == limayaml.VIRTIOFS {
		for i, f := range y.Mounts {
			tag := fmt.Sprintf("mount%d", i)
			if err := os.MkdirAll(f.Location, 0o755); err != nil {
				return "", nil, err
			}

			switch *y.MountType {
			case limayaml.NINEP:
				options := "local"
				options += fmt.Sprintf(",mount_tag=%s", tag)
				options += fmt.Sprintf(",path=%s", f.Location)
				options += fmt.Sprintf(",security_model=%s", *f.NineP.SecurityModel)
				if !*f.Writable {
					options += ",readonly"
				}
				args = append(args, "-virtfs", options)
			case limayaml.VIRTIOFS:
				// Note that read-only mode is not supported on the QEMU/virtiofsd side yet:
				// https://gitlab.com/virtio-fs/virtiofsd/-/issues/97
				chardev := fmt.Sprintf("char-virtiofs-%d", i)
				vhostSock := filepath.Join(cfg.InstanceDir, fmt.Sprintf(filenames.VhostSock, i))
				args = append(args, "-chardev", fmt.Sprintf("socket,id=%s,path=%s", chardev, vhostSock))

				options := "vhost-user-fs-pci"
				options += fmt.Sprintf(",queue-size=%d", *f.Virtiofs.QueueSize)
				options += fmt.Sprintf(",chardev=%s", chardev)
				options += fmt.Sprintf(",tag=%s", tag)
				args = append(args, "-device", options)
			}
		}
	}

	// QMP
	qmpSock := filepath.Join(cfg.InstanceDir, filenames.QMPSock)
	if err := os.RemoveAll(qmpSock); err != nil {
		return "", nil, err
	}
	const qmpChardev = "char-qmp"
	args = append(args, "-chardev", fmt.Sprintf("socket,id=%s,path=%s,server=on,wait=off", qmpChardev, qmpSock))
	args = append(args, "-qmp", "chardev:"+qmpChardev)

	// QEMU process
	args = append(args, "-name", "lima-"+cfg.Name)
	args = append(args, "-pidfile", filepath.Join(cfg.InstanceDir, filenames.PIDFile(*y.VMType)))

	return exe, args, nil
}

func FindVirtiofsd(qemuExe string) (string, error) {
	type vhostUserBackend struct {
		BackendType string `json:"type"`
		Binary      string `json:"binary"`
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	const relativePath = "share/qemu/vhost-user"

	binDir := filepath.Dir(qemuExe)                  // "/usr/local/bin"
	usrDir := filepath.Dir(binDir)                   // "/usr/local"
	userLocalDir := filepath.Join(homeDir, ".local") // "$HOME/.local"

	candidates := []string{
		filepath.Join(userLocalDir, relativePath),
		filepath.Join(usrDir, relativePath),
	}

	if usrDir != "/usr" {
		candidates = append(candidates, filepath.Join("/usr", relativePath))
	}

	for _, vhostCfgsDir := range candidates {
		logrus.Debugf("Checking vhost directory %s", vhostCfgsDir)

		cfgEntries, err := os.ReadDir(vhostCfgsDir)
		if err != nil {
			logrus.Debugf("Failed to list vhost directory: %v", err)
			continue
		}

		for _, cfgEntry := range cfgEntries {
			logrus.Debugf("Checking vhost vhostCfg %s", cfgEntry.Name())
			if !strings.HasSuffix(cfgEntry.Name(), ".json") {
				continue
			}

			var vhostCfg vhostUserBackend
			contents, err := os.ReadFile(filepath.Join(vhostCfgsDir, cfgEntry.Name()))
			if err == nil {
				err = json.Unmarshal(contents, &vhostCfg)
			}

			if err != nil {
				logrus.Warnf("Failed to load vhost-user config %s: %v", cfgEntry.Name(), err)
				continue
			}
			logrus.Debugf("%v", vhostCfg)

			if vhostCfg.BackendType != "fs" {
				continue
			}

			// Only rust virtiofsd supports --version, so use that to make sure this isn't
			// QEMU's virtiofsd, which requires running as root.
			cmd := exec.Command(vhostCfg.Binary, "--version")
			output, err := cmd.CombinedOutput()
			if err != nil {
				logrus.Warnf("Failed to run %s --version (is this QEMU virtiofsd?): %s: %s",
					vhostCfg.Binary, err, output)
				continue
			}

			return vhostCfg.Binary, nil
		}
	}

	return "", errors.New("failed to locate virtiofsd")
}

func VirtiofsdCmdline(cfg Config, mountIndex int) ([]string, error) {
	mount := cfg.LimaYAML.Mounts[mountIndex]

	vhostSock := filepath.Join(cfg.InstanceDir, fmt.Sprintf(filenames.VhostSock, mountIndex))
	// qemu_driver has to wait for the socket to appear, so make sure any old ones are removed here.
	if err := os.Remove(vhostSock); err != nil && !errors.Is(err, fs.ErrNotExist) {
		logrus.Warnf("Failed to remove old vhost socket: %v", err)
	}

	return []string{
		"--socket-path", vhostSock,
		"--shared-dir", mount.Location,
	}, nil
}

// qemuArch returns the arch string used by qemu.
func qemuArch(arch limayaml.Arch) string {
	switch arch {
	case limayaml.ARMV7L:
		return "arm"
	case limayaml.PPC64LE:
		return "ppc64"
	default:
		return arch
	}
}

// qemuEdk2 returns the arch string used by `/usr/local/share/qemu/edk2-*-code.fd`.
func qemuEdk2Arch(arch limayaml.Arch) string {
	if arch == limayaml.RISCV64 {
		return "riscv"
	}
	return qemuArch(arch)
}

func Exe(arch limayaml.Arch) (exe string, args []string, err error) {
	exeBase := "qemu-system-" + qemuArch(arch)
	envK := "QEMU_SYSTEM_" + strings.ToUpper(qemuArch(arch))
	if envV := os.Getenv(envK); envV != "" {
		ss, err := shellwords.Parse(envV)
		if err != nil {
			return "", nil, fmt.Errorf("failed to parse %s value %q: %w", envK, envV, err)
		}
		exeBase, args = ss[0], ss[1:]
		if len(args) != 0 {
			logrus.Warnf("Specifying args (%v) via $%s is supported only for debugging!", args, envK)
		}
	}
	exe, err = exec.LookPath(exeBase)
	if err != nil {
		return "", nil, err
	}
	return exe, args, nil
}

func Accel(arch limayaml.Arch) string {
	if limayaml.IsNativeArch(arch) {
		switch runtime.GOOS {
		case "darwin":
			return "hvf"
		case "linux":
			return "kvm"
		case "netbsd":
			return "nvmm"
		case "dragonfly":
			return "nvmm"
		case "windows":
			return "whpx"
		}
	}
	return "tcg"
}
