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
	"os/exec"
	"path/filepath"

	"github.com/luthermonson/go-proxmox"
	"github.com/sirupsen/logrus"

	"github.com/lima-vm/lima/v2/pkg/driver"
	"github.com/lima-vm/lima/v2/pkg/executil"
	"github.com/lima-vm/lima/v2/pkg/limatype"
	"github.com/lima-vm/lima/v2/pkg/ptr"
)

type LimaProxmoxDriver struct {
	Instance     *limatype.Instance
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

func (l *LimaProxmoxDriver) Configure(inst *limatype.Instance) *driver.ConfiguredDriver {
	l.Instance = inst
	l.SSHLocalPort = inst.SSHLocalPort

	return &driver.ConfiguredDriver{
		Driver: l,
	}
}

func (l *LimaProxmoxDriver) Validate(ctx context.Context) error {
	return validateConfig(ctx, l.Instance.Config)
}

func validateConfig(ctx context.Context, cfg *limatype.LimaYAML) error {
	if cfg == nil {
		return errors.New("configuration is nil")
	}
	if *cfg.MountType != limatype.REVSSHFS {
		return fmt.Errorf("field `mountType` must be %q for %s driver, got %q",
			limatype.REVSSHFS, "proxmox", *cfg.MountType)
	}
	return nil
}
func (l *LimaProxmoxDriver) FillConfig(ctx context.Context, cfg *limatype.LimaYAML, filePath string) error {
	if cfg.VMType == nil {
		cfg.VMType = ptr.Of("proxmox")
	}

	return validateConfig(ctx, cfg)
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

func logPipeRoutine(r io.Reader, header string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		logrus.Debugf("%s: %s", header, line)
	}
}

func (l *LimaProxmoxDriver) Info() driver.Info {
	var info driver.Info
	info.Name = "proxmox"
	if l.Instance != nil && l.Instance.Dir != "" {
		info.InstanceDir = l.Instance.Dir
	}

	info.Features = driver.DriverFeatures{
		DynamicSSHAddress:    false,
		SkipSocketForwarding: false,
		CanRunGUI:            false,
	}
	return info
}

func (l *LimaProxmoxDriver) SSHAddress(_ context.Context) (string, error) {
	return "127.0.0.1", nil
}

func (l *LimaProxmoxDriver) InspectStatus(_ context.Context, _ *limatype.Instance) string {
	return ""
}

func (l *LimaProxmoxDriver) Initialize(_ context.Context) error {
	return nil
}

func (l *LimaProxmoxDriver) Create(_ context.Context) error {
	return nil
}

func (l *LimaProxmoxDriver) Delete(_ context.Context) error {
	return nil
}

func (l *LimaProxmoxDriver) BootScripts() (map[string][]byte, error) {
	return nil, nil
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
