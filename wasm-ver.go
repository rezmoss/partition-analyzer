package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"syscall/js"
)

const (
	MBR_SIGNATURE = 0xAA55
	GPT_SIGNATURE = "EFI PART"
	SECTOR_SIZE   = 512
)

type MBRPartition struct {
	Status     uint8
	StartCHS   [3]uint8
	Type       uint8
	EndCHS     [3]uint8
	StartLBA   uint32
	SizeBlocks uint32
}

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

type GPTPartition struct {
	TypeGUID      [16]byte
	PartitionGUID [16]byte
	StartLBA      uint64
	EndLBA        uint64
	Attributes    uint64
	Name          [72]byte
}

type PartitionInfo struct {
	Number      int     `json:"number"`
	Status      string  `json:"status,omitempty"`
	Type        string  `json:"type,omitempty"`
	StartLBA    uint64  `json:"startLBA,omitempty"`
	EndLBA      uint64  `json:"endLBA,omitempty"`
	SizeGB      float64 `json:"sizeGB,omitempty"`
	Description string  `json:"description,omitempty"`
	Name        string  `json:"name,omitempty"`
	Info        string  `json:"info,omitempty"`
	Note        string  `json:"note,omitempty"`
}

type AnalysisResult struct {
	Filename    string          `json:"filename"`
	TableType   string          `json:"tableType"`
	Partitions  []PartitionInfo `json:"partitions"`
	Error       string          `json:"error,omitempty"`
	GPTRevision string          `json:"gptRevision,omitempty"`
}

func main() {
	c := make(chan struct{}, 0)

	// Register the function to be called from JavaScript
	js.Global().Set("analyzeDiskImageGo", js.FuncOf(analyzeDiskImageWrapper))

	fmt.Println("Go WebAssembly initialized")
	<-c
}

func analyzeDiskImageWrapper(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return map[string]interface{}{
			"error": "Missing arguments: need data and filename",
		}
	}

	// Get the Uint8Array from JavaScript
	dataJS := args[0]
	filename := args[1].String()

	// Convert JavaScript Uint8Array to Go byte slice
	dataLen := dataJS.Get("length").Int()
	data := make([]byte, dataLen)
	js.CopyBytesToGo(data, dataJS)

	result := analyzeDiskImage(data, filename)

	// Convert result to JavaScript object
	resultJSON, _ := json.Marshal(result)
	var resultMap map[string]interface{}
	json.Unmarshal(resultJSON, &resultMap)

	return resultMap
}

func analyzeDiskImage(data []byte, filename string) AnalysisResult {
	result := AnalysisResult{
		Filename:   filename,
		Partitions: []PartitionInfo{},
	}

	if len(data) < SECTOR_SIZE {
		result.Error = "Data too small to contain MBR"
		return result
	}

	// Check MBR signature
	signature := binary.LittleEndian.Uint16(data[510:512])
	if signature != MBR_SIGNATURE {
		result.Error = "Invalid MBR signature"
		return result
	}

	// Check if it's GPT by looking at partition type of first entry
	firstPartType := data[446+4]
	if firstPartType == 0xEE {
		result.TableType = "GPT"
		result.Partitions = readGPTPartitions(data)
	} else {
		result.TableType = "MBR"
		result.Partitions = readMBRPartitions(data)
	}

	return result
}

func readMBRPartitions(data []byte) []PartitionInfo {
	var partitions []PartitionInfo

	for i := 0; i < 4; i++ {
		offset := 446 + (i * 16)

		status := data[offset]
		partType := data[offset+4]
		startLBA := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		sizeBlocks := binary.LittleEndian.Uint32(data[offset+12 : offset+16])

		if partType != 0 {
			statusStr := "Inactive"
			if status == 0x80 {
				statusStr = "Active"
			}

			sizeGB := float64(sizeBlocks*SECTOR_SIZE) / (1024 * 1024 * 1024)
			typeDesc := getMBRTypeDescription(partType)

			partition := PartitionInfo{
				Number:      i + 1,
				Status:      statusStr,
				Type:        fmt.Sprintf("0x%02X", partType),
				StartLBA:    uint64(startLBA),
				SizeGB:      sizeGB,
				Description: typeDesc,
			}

			partitions = append(partitions, partition)
		}
	}

	return partitions
}

func readGPTPartitions(data []byte) []PartitionInfo {
	var partitions []PartitionInfo

	// Check if we have enough data for GPT header (need at least 2 sectors)
	if len(data) < SECTOR_SIZE*2 {
		partitions = append(partitions, PartitionInfo{
			Number: 1,
			Info:   "GPT detected but insufficient data",
			Note:   "Need at least 1KB of data to read GPT header",
		})
		return partitions
	}

	// Read GPT header from second sector
	headerBytes := data[SECTOR_SIZE : SECTOR_SIZE*2]

	// Verify GPT signature
	if string(headerBytes[0:8]) != GPT_SIGNATURE {
		partitions = append(partitions, PartitionInfo{
			Number: 1,
			Info:   "Invalid GPT signature in header",
			Note:   "GPT structure may be corrupted",
		})
		return partitions
	}

	// Parse GPT header
	revision := binary.LittleEndian.Uint32(headerBytes[8:12])
	numPartitions := binary.LittleEndian.Uint32(headerBytes[80:84])
	partitionEntrySize := binary.LittleEndian.Uint32(headerBytes[84:88])
	partitionTableLBA := binary.LittleEndian.Uint64(headerBytes[72:80])

	// Calculate required data size for partition table
	requiredSize := int(partitionTableLBA*SECTOR_SIZE) + int(numPartitions*partitionEntrySize)

	if len(data) < requiredSize {
		partitions = append(partitions, PartitionInfo{
			Number: 1,
			Info:   fmt.Sprintf("GPT detected (Rev %d.%d, %d partitions)", revision>>16, revision&0xFFFF, numPartitions),
			Note:   fmt.Sprintf("Need at least %d bytes to read all partition entries", requiredSize),
		})
		return partitions
	}

	// Read partition entries
	partitionTableOffset := int(partitionTableLBA * SECTOR_SIZE)
	partCount := 0

	for i := uint32(0); i < numPartitions && partitionTableOffset+int(i*partitionEntrySize)+int(partitionEntrySize) <= len(data); i++ {
		entryOffset := partitionTableOffset + int(i*partitionEntrySize)
		partBytes := data[entryOffset : entryOffset+int(partitionEntrySize)]

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
			for j := 56; j < 56+72 && j+1 < len(partBytes); j += 2 {
				if partBytes[j] == 0 && partBytes[j+1] == 0 {
					break
				}
				if partBytes[j+1] == 0 && partBytes[j] >= 32 && partBytes[j] <= 126 {
					name += string(partBytes[j])
				}
			}
			if name == "" {
				name = "Unnamed"
			}

			sizeGB := float64((endLBA-startLBA+1)*SECTOR_SIZE) / (1024 * 1024 * 1024)

			partition := PartitionInfo{
				Number:   partCount,
				StartLBA: startLBA,
				EndLBA:   endLBA,
				SizeGB:   sizeGB,
				Name:     name,
			}

			partitions = append(partitions, partition)
		}
	}

	if len(partitions) == 0 {
		partitions = append(partitions, PartitionInfo{
			Number: 1,
			Info:   fmt.Sprintf("GPT structure valid (Rev %d.%d)", revision>>16, revision&0xFFFF),
			Note:   "No active partitions found in partition table",
		})
	}

	return partitions
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
