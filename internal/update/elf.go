package update

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// elfMachine codes for the architectures RONDA ships.
const (
	elfMachineX86_64  = 62  // EM_X86_64
	elfMachineAArch64 = 183 // EM_AARCH64
)

// checkELFArch verifies that path is an ELF object whose e_machine field
// matches wantArch ("amd64" or "arm64"). The installer-independent Go side of
// architecture verification: a checksum can only prove the download matches
// the signed bytes, not that those bytes can run on this machine.
func checkELFArch(path, wantArch string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var head [20]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return fmt.Errorf("ronda update: artifact too short to be an ELF binary: %w", err)
	}
	if head[0] != 0x7f || head[1] != 'E' || head[2] != 'L' || head[3] != 'F' {
		return fmt.Errorf("ronda update: downloaded artifact is not an ELF binary")
	}
	want, err := machineForArch(wantArch)
	if err != nil {
		return err
	}
	got := binary.LittleEndian.Uint16(head[18:20])
	if int(got) != want {
		return fmt.Errorf("ronda update: ELF architecture mismatch: artifact targets e_machine %d, want %d (%s)", got, want, wantArch)
	}
	return nil
}

func machineForArch(arch string) (int, error) {
	switch arch {
	case "amd64":
		return elfMachineX86_64, nil
	case "arm64":
		return elfMachineAArch64, nil
	default:
		return 0, fmt.Errorf("ronda update: unsupported architecture %q", arch)
	}
}
