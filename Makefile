
GO = go

lima-driver-proxmox: cmd/lima-driver-proxmox pkg/driver/proxmox go.mod
	$(GO) build ./cmd/lima-driver-proxmox
