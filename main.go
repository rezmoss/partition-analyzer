package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

const (
	MBR_SIGNATURE = 0xAA55
	GPT_SIGNATURE = "EFI PART"
	SECTOR_SIZE   = 512
)

// MBR Partition Entry (16 bytes)
type MBRPartition struct {
	Status     uint8
	StartCHS   [3]uint8
	Type       uint8
	EndCHS     [3]uint8
	StartLBA   uint32
	SizeBlocks uint32
}

// GPT Header (first 92 bytes we care about)
type GPTHeader struct {
	Signature          [8]byte
	Revision           uint32
	HeaderSize         uint32
	HeaderCRC32        uint32
	Reserved           uint32
	CurrentLBA         uint64
	BackupLBA          uint64
	FirstUsableLBA     uint64
	LastUsableLBA      uint64
	DiskGUID           [16]byte
	PartitionTableLBA  uint64
	NumPartitions      uint32
	PartitionEntrySize uint32
	PartitionTableCRC  uint32
}

// GPT Partition Entry (128 bytes)
type GPTPartition struct {
	TypeGUID      [16]byte
	PartitionGUID [16]byte
	StartLBA      uint64
	EndLBA        uint64
	Attributes    uint64
	Name          [72]byte // UTF-16LE
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <disk_image_file>\n", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Read first sector (MBR)
	mbr := make([]byte, SECTOR_SIZE)
	n, err := file.Read(mbr)
	if err != nil || n != SECTOR_SIZE {
		fmt.Printf("Error reading MBR: %v\n", err)
		os.Exit(1)
	}

	// Check MBR signature
	signature := binary.LittleEndian.Uint16(mbr[510:512])
	if signature != MBR_SIGNATURE {
		fmt.Println("Invalid MBR signature")
		os.Exit(1)
	}

	fmt.Printf("Disk Image: %s\n", filename)
	fmt.Println("=" + string(make([]byte, len(filename)+12)))

	// Check if it's GPT by looking at partition type of first entry
	firstPartType := mbr[446+4] // First partition type byte
	if firstPartType == 0xEE {
		// This is GPT
		fmt.Println("Partition Table Type: GPT")
		readGPTPartitions(file)
	} else {
		// This is MBR
		fmt.Println("Partition Table Type: MBR")
		readMBRPartitions(mbr)
	}
}

func readMBRPartitions(mbr []byte) {
	fmt.Println("\nPartitions:")
	fmt.Printf("%-4s %-8s %-12s %-12s %-12s %s\n",
		"#", "Status", "Type", "Start LBA", "Size", "Description")
	fmt.Println(string(make([]byte, 70)))

	partCount := 0
	for i := 0; i < 4; i++ {
		offset := 446 + (i * 16)

		status := mbr[offset]
		partType := mbr[offset+4]
		startLBA := binary.LittleEndian.Uint32(mbr[offset+8 : offset+12])
		sizeBlocks := binary.LittleEndian.Uint32(mbr[offset+12 : offset+16])

		if partType != 0 {
			partCount++
			statusStr := "Inactive"
			if status == 0x80 {
				statusStr = "Active"
			}

			sizeGB := float64(sizeBlocks*SECTOR_SIZE) / (1024 * 1024 * 1024)
			typeDesc := getMBRTypeDescription(partType)

			fmt.Printf("%-4d %-8s 0x%-10X %-12d %-12.2f %s\n",
				i+1, statusStr, partType, startLBA, sizeGB, typeDesc)
		}
	}

	if partCount == 0 {
		fmt.Println("No partitions found")
	}
}

func readGPTPartitions(file *os.File) {
	// Read GPT header from LBA 1
	file.Seek(SECTOR_SIZE, 0)
	headerBytes := make([]byte, 512)
	n, err := file.Read(headerBytes)
	if err != nil || n != 512 {
		fmt.Printf("Error reading GPT header: %v\n", err)
		return
	}

	// Parse GPT header
	var header GPTHeader
	header.Signature = *(*[8]byte)(headerBytes[0:8])
	header.Revision = binary.LittleEndian.Uint32(headerBytes[8:12])
	header.HeaderSize = binary.LittleEndian.Uint32(headerBytes[12:16])
	header.NumPartitions = binary.LittleEndian.Uint32(headerBytes[80:84])
	header.PartitionEntrySize = binary.LittleEndian.Uint32(headerBytes[84:88])
	header.PartitionTableLBA = binary.LittleEndian.Uint64(headerBytes[72:80])

	// Verify GPT signature
	if string(header.Signature[:]) != GPT_SIGNATURE {
		fmt.Println("Invalid GPT signature")
		return
	}

	fmt.Printf("GPT Revision: %d.%d\n", header.Revision>>16, header.Revision&0xFFFF)
	fmt.Printf("Number of Partitions: %d\n", header.NumPartitions)

	// Read partition entries
	file.Seek(int64(header.PartitionTableLBA*SECTOR_SIZE), 0)

	fmt.Println("\nPartitions:")
	fmt.Printf("%-4s %-12s %-12s %-12s %s\n",
		"#", "Start LBA", "End LBA", "Size", "Name")
	fmt.Println(string(make([]byte, 60)))

	partCount := 0
	for i := uint32(0); i < header.NumPartitions; i++ {
		partBytes := make([]byte, header.PartitionEntrySize)
		n, err := file.Read(partBytes)
		if err != nil || uint32(n) != header.PartitionEntrySize {
			break
		}

		// Check if partition entry is used (non-zero type GUID)
		allZero := true
		for j := 0; j < 16; j++ {
			if partBytes[j] != 0 {
				allZero = false
				break
			}
		}

		if !allZero {
			partCount++
			startLBA := binary.LittleEndian.Uint64(partBytes[32:40])
			endLBA := binary.LittleEndian.Uint64(partBytes[40:48])

			// Convert UTF-16LE name to string (simplified)
			name := ""
			for j := 56; j < 56+72; j += 2 {
				if partBytes[j] == 0 && partBytes[j+1] == 0 {
					break
				}
				if partBytes[j+1] == 0 {
					name += string(partBytes[j])
				}
			}
			if name == "" {
				name = "Unnamed"
			}

			sizeGB := float64((endLBA-startLBA+1)*SECTOR_SIZE) / (1024 * 1024 * 1024)

			fmt.Printf("%-4d %-12d %-12d %-12.2f %s\n",
				partCount, startLBA, endLBA, sizeGB, name)
		}
	}

	if partCount == 0 {
		fmt.Println("No partitions found")
	}
}

func getMBRTypeDescription(partType uint8) string {
	descriptions := map[uint8]string{
		0x00: "Empty",
		0x01: "FAT12",
		0x04: "FAT16 <32M",
		0x05: "Extended",
		0x06: "FAT16",
		0x07: "HPFS/NTFS/exFAT",
		0x0B: "W95 FAT32",
		0x0C: "W95 FAT32 (LBA)",
		0x0E: "W95 FAT16 (LBA)",
		0x0F: "W95 Ext'd (LBA)",
		0x11: "Hidden FAT12",
		0x14: "Hidden FAT16 <32M",
		0x16: "Hidden FAT16",
		0x17: "Hidden HPFS/NTFS",
		0x1B: "Hidden W95 FAT32",
		0x1C: "Hidden W95 FAT32 (LBA)",
		0x1E: "Hidden W95 FAT16 (LBA)",
		0x82: "Linux swap",
		0x83: "Linux",
		0x85: "Linux extended",
		0x8E: "Linux LVM",
		0xA0: "Hibernation",
		0xA5: "FreeBSD",
		0xA6: "OpenBSD",
		0xA8: "Darwin UFS",
		0xA9: "NetBSD",
		0xAB: "Darwin boot",
		0xAF: "HFS / HFS+",
		0xBE: "Solaris boot",
		0xBF: "Solaris",
		0xEB: "BeOS fs",
		0xEE: "GPT",
		0xEF: "EFI (FAT-12/16/32)",
		0xFB: "VMware VMFS",
		0xFC: "VMware VMKCORE",
		0xFD: "Linux raid autodetect",
	}

	if desc, exists := descriptions[partType]; exists {
		return desc
	}
	return "Unknown"
}
