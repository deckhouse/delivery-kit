package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
)

func main() {
	b, _ := os.ReadFile("test_elf_lin")
	r := bytes.NewReader(b)
	ef, err := elf.NewFile(r)
	if err != nil {
		fmt.Println("NewFile err:", err)
		return
	}
	fmt.Println(ef.Machine)
	
	// manually parse
	machine := parseElfMachine(b[:64])
	fmt.Println("parsed:", machine)
}

func parseElfMachine(b []byte) elf.Machine {
    if len(b) < 64 || string(b[:4]) != "\x7fELF" {
        return 0
    }
    class := elf.Class(b[elf.EI_CLASS])
    data := elf.Data(b[elf.EI_DATA])
    var machine uint16
    if class == elf.ELFCLASS32 {
        if data == elf.ELFDATA2LSB {
            machine = uint16(b[18]) | uint16(b[19])<<8
        } else {
            machine = uint16(b[19]) | uint16(b[18])<<8
        }
    } else if class == elf.ELFCLASS64 {
        if data == elf.ELFDATA2LSB {
            machine = uint16(b[18]) | uint16(b[19])<<8
        } else {
            machine = uint16(b[19]) | uint16(b[18])<<8
        }
    }
    return elf.Machine(machine)
}
