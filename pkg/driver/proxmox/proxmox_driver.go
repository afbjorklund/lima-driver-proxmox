// SPDX-FileCopyrightText: Copyright The Lima Authors
// SPDX-License-Identifier: Apache-2.0

package proxmox

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/luthermonson/go-proxmox"
	"github.com/sirupsen/logrus"

	"github.com/lima-vm/lima/v2/pkg/driver"
	"github.com/lima-vm/lima/v2/pkg/executil"
	"github.com/lima-vm/lima/v2/pkg/limayaml"
	"github.com/lima-vm/lima/v2/pkg/store"
)

type LimaProxmoxDriver struct {
	Instance     *store.Instance
	SSHLocalPort int

	qCmd    *exec.Cmd
	qWaitCh chan error

	client   *proxmox.Client
	ID       int
	node     *proxmox.Node
	template *proxmox.VirtualMachine
	vm       *proxmox.VirtualMachine
}

var _ driver.Driver = (*LimaProxmoxDriver)(nil)

func New() *LimaProxmoxDriver {
	return &LimaProxmoxDriver{}
}

func (l *LimaProxmoxDriver) Configure(inst *store.Instance) *driver.ConfiguredDriver {
	l.Instance = inst
	l.SSHLocalPort = inst.SSHLocalPort

	return &driver.ConfiguredDriver{
		Driver: l,
	}
}

func (l *LimaProxmoxDriver) Validate() error {
	if *l.Instance.Config.MountType != limayaml.REVSSHFS {
		return fmt.Errorf("field `mountType` must be %q for %s driver, got %q",
			limayaml.REVSSHFS, "proxmox", *l.Instance.Config.MountType)
	}
	return nil
}

func (l *LimaProxmoxDriver) Start(_ context.Context) (chan error, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		if l.qCmd == nil {
			cancel()
		}
	}()

	qCfg := Config{
		Name:         l.Instance.Name,
		InstanceDir:  l.Instance.Dir,
		LimaYAML:     l.Instance.Config,
		SSHLocalPort: l.SSHLocalPort,
		SSHAddress:   l.Instance.SSHAddress,
	}

	var qArgsFinal []string
	qCmd := exec.CommandContext(ctx, "proxmox", qArgsFinal...)
	qCmd.SysProcAttr = executil.BackgroundSysProcAttr
	qStdout, err := qCmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	go logPipeRoutine(qStdout, "proxmox[stdout]")
	qStderr, err := qCmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	go logPipeRoutine(qStderr, "proxmox[stderr]")

	logrus.Infof("Starting QEMU (hint: to watch the boot progress, see %q)", filepath.Join(qCfg.InstanceDir, "serial*.log"))
	if err := qCmd.Start(); err != nil {
		return nil, err
	}

	l.qWaitCh = make(chan error, 1)

	return l.qWaitCh, nil
}

func (l *LimaProxmoxDriver) Stop(ctx context.Context) error {
	return errUnimplemented
}

func (l *LimaProxmoxDriver) GuestAgentConn(ctx context.Context) (net.Conn, string, error) {
	return nil, "", nil
}

func waitFileExists(path string, timeout time.Duration) error {
	startWaiting := time.Now()
	for {
		_, err := os.Stat(path)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if time.Since(startWaiting) > timeout {
			return fmt.Errorf("timeout waiting for %s", path)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

func (l *LimaProxmoxDriver) killQEMU(_ context.Context, _ time.Duration, qCmd *exec.Cmd, qWaitCh <-chan error) error {
	var qWaitErr error
	if qCmd.ProcessState == nil {
		if killErr := qCmd.Process.Kill(); killErr != nil {
			logrus.WithError(killErr).Warn("failed to kill QEMU")
		}
		qWaitErr = <-qWaitCh
		logrus.WithError(qWaitErr).Info("QEMU has exited, after killing forcibly")
	} else {
		logrus.Info("QEMU has already exited")
	}
	return qWaitErr
}

func logPipeRoutine(r io.Reader, header string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		logrus.Debugf("%s: %s", header, line)
	}
}

func (l *LimaProxmoxDriver) Info() driver.Info {
	var info driver.Info
	if l.Instance != nil && l.Instance.Dir != "" {
		info.InstanceDir = l.Instance.Dir
	}
	info.DriverName = "proxmox"
	info.CanRunGUI = false
	return info
}

func (l *LimaProxmoxDriver) Initialize(_ context.Context) error {
	return nil
}

func (l *LimaProxmoxDriver) CreateDisk(_ context.Context) error {
	return nil
}

func (l *LimaProxmoxDriver) RunGUI() error {
	return nil
}

func (l *LimaProxmoxDriver) Register(_ context.Context) error {
	return nil
}

func (l *LimaProxmoxDriver) Unregister(_ context.Context) error {
	return nil
}

func (l *LimaProxmoxDriver) ChangeDisplayPassword(_ context.Context, _ string) error {
	return nil
}

func (l *LimaProxmoxDriver) DisplayConnection(_ context.Context) (string, error) {
	return "", nil
}

func (l *LimaProxmoxDriver) CreateSnapshot(_ context.Context, _ string) error {
	return errUnimplemented
}

func (l *LimaProxmoxDriver) ApplySnapshot(_ context.Context, _ string) error {
	return errUnimplemented
}

func (l *LimaProxmoxDriver) DeleteSnapshot(_ context.Context, _ string) error {
	return errUnimplemented
}

func (l *LimaProxmoxDriver) ListSnapshots(_ context.Context) (string, error) {
	return "", errUnimplemented
}

func (l *LimaProxmoxDriver) ForwardGuestAgent() bool {
	// if driver is not providing, use host agent
	return true
}
