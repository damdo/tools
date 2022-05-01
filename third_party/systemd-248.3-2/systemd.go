// Package systemd provides a bundled copy of the systemd-boot UEFI app.
package systemd

import "embed"

//go:embed systemd-bootx64.efi
var SystemdBootX64 embed.FS

//go:embed BOOTAA64.EFI
var SystemdBootAArch64 embed.FS

//go:embed grub.efi
var SystemdBootGrub embed.FS

//go:embed grub.cfg
var SystemdBootGrubCfg embed.FS
