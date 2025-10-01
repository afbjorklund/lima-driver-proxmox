// SPDX-FileCopyrightText: Copyright The Lima Authors
// SPDX-License-Identifier: Apache-2.0

package proxmox

import (
	"context"
)

func (l *LimaProxmoxDriver) Create(_ context.Context) error {
	return nil
}

func (l *LimaProxmoxDriver) Delete(_ context.Context) error {
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
