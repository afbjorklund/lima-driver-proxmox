// SPDX-FileCopyrightText: Copyright The Lima Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	"github.com/afbjorklund/lima-driver-proxmox/pkg/driver/proxmox"
	"github.com/lima-vm/lima/v2/pkg/driver/external/server"
)

// To be used as an external driver for Lima.
func main() {
	server.Serve(context.Background(), proxmox.New())
}
