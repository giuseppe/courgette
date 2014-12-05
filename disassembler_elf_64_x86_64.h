// Copyright 2013, 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COURGETTE_DISASSEMBLER_ELF_64_H_
#define COURGETTE_DISASSEMBLER_ELF_64_H_

#include "courgette/disassembler_elf_32_x86.h"

namespace courgette {

class AssemblyProgram;

class DisassemblerElf64X86_64 : public DisassemblerElf32X86 {

 public:
  explicit DisassemblerElf64X86_64(const void* start, size_t length);

  virtual ~DisassemblerElf64X86_64() { };

  virtual ExecutableType kind() {return EXE_ELF_64_X86_64;}

  virtual e_machine_values ElfEM() {return EM_x86_64;}

  virtual bool ParseHeader();

  virtual bool Disassemble(AssemblyProgram* target);

 protected:

  CheckBool IsValidRVA(RVA rva) const WARN_UNUSED_RESULT;

  Elf64_Shdr *section_header_table_;
  Elf64_Half section_header_table_size_;

  CheckBool ParseRelocationSection(const Elf64_Shdr *section_header,
                                   AssemblyProgram* program);

  CheckBool ParseSimpleRegion(size_t start_file_offset,
                              size_t end_file_offset,
                              AssemblyProgram* program) WARN_UNUSED_RESULT;

  uint32 DiscoverLength();

  const Elf64_Shdr *SectionHeader(int id) const {
    assert(id >= 0 && id < SectionHeaderCount());
    return section_header_table_ + id;
  }

  Elf64_Half SectionHeaderCount() const {
    return section_header_table_size_;
  }

  Elf64_Half ProgramSegmentHeaderCount() const {
    return program_header_table_size_;
  }

  const Elf64_Phdr *ProgramSegmentHeader(int id) const {
    assert(id >= 0 && id < ProgramSegmentHeaderCount());
    return program_header_table_ + id;
  }

  CheckBool ParseRel32RelocsFromSections() WARN_UNUSED_RESULT;
  virtual CheckBool ParseRel32RelocsFromSection(const Elf64_Shdr* section) WARN_UNUSED_RESULT;

  // The virtual memory address at which this program segment will be loaded
  Elf64_Addr ProgramSegmentMemoryBegin(int id) const {
    return ProgramSegmentHeader(id)->p_vaddr;
  }

  // The number of virtual memory bytes for this program segment
  Elf64_Word ProgramSegmentMemorySize(int id) const {
    return ProgramSegmentHeader(id)->p_memsz;
  }

  // Pointer into the source file for this program segment
  Elf64_Addr ProgramSegmentFileOffset(int id) const {
    return ProgramSegmentHeader(id)->p_offset;
  }

  // Number of file bytes for this program segment. Is <= ProgramMemorySize.
  Elf64_Word ProgramSegmentFileSize(int id) const {
    return ProgramSegmentHeader(id)->p_filesz;
  }

  Elf64_Phdr *program_header_table_;
  Elf64_Half program_header_table_size_;

  Elf64_Ehdr *header_;

  CheckBool ParseProgbitsSection(AssemblyProgram* program,
                                 ScopedVector<TypedRVA>::iterator* current_rel,
                                 ScopedVector<TypedRVA>::iterator end_rel,
                                 const Elf64_Shdr *section_header);
  CheckBool ParseFile(AssemblyProgram* target) WARN_UNUSED_RESULT;

  ScopedVector<TypedRVA> rel32_locations_;

  DISALLOW_COPY_AND_ASSIGN(DisassemblerElf64X86_64);
};

}  // namespace courgette

#endif  // COURGETTE_DISASSEMBLER_ELF_64_H_
