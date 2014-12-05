// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COURGETTE_DISASSEMBLER_ELF_64_H_
#define COURGETTE_DISASSEMBLER_ELF_64_H_

#include "base/basictypes.h"
#include "base/memory/scoped_vector.h"
#include "courgette/assembly_program.h"
#include "courgette/disassembler.h"
#include "courgette/memory_allocator.h"
#include "courgette/types_elf.h"

namespace courgette {

class AssemblyProgram;

class DisassemblerElf64X86_64 : public Disassembler {

 public:
  explicit DisassemblerElf64X86_64(const void* start, size_t length);

  virtual ~DisassemblerElf64X86_64() { };

  virtual ExecutableType kind() {return EXE_ELF_64_X86_64;}

  virtual e_machine_values ElfEM() {return EM_x86_64;}

  virtual bool ParseHeader();

  virtual bool Disassemble(AssemblyProgram* target);

 protected:

  class TypedRVA {
   public:
    explicit TypedRVA(RVA rva) : rva_(rva), offset_(static_cast<size_t>(-1)) {
    }

    virtual ~TypedRVA() { };

    RVA rva() {
      return rva_;
    }

    RVA relative_target() {
      return relative_target_;
    }

    void set_relative_target(RVA relative_target) {
      relative_target_ = relative_target;
    }

    size_t get_offset() {
      return offset_;
    }

    void set_offset(size_t offset) {
      offset_ = offset;
    }

    virtual uint16 op_size() {return 4;}

    static bool IsLessThan(TypedRVA *a, TypedRVA *b) {
      return a->rva() < b->rva();
    }
  private:
    const RVA rva_;
    RVA relative_target_;
    size_t offset_;
  };

  class TypedRVA64 {
   public:
    explicit TypedRVA64(RVA64 rva) : rva_(rva), offset_(static_cast<size_t>(-1)) {
    }

    virtual ~TypedRVA64() { };

    RVA64 rva() {
      return rva_;
    }

    RVA64 relative_target() {
      return relative_target_;
    }

    void set_relative_target(RVA64 relative_target) {
      relative_target_ = relative_target;
    }

    size_t get_offset() {
      return offset_;
    }

    void set_offset(size_t offset) {
      offset_ = offset;
    }

    virtual uint16 op_size() {return 4;}

    static bool IsLessThan(TypedRVA64 *a, TypedRVA64 *b) {
      return a->rva() < b->rva();
    }
  private:
    const RVA64 rva_;
    RVA64 relative_target_;
    size_t offset_;
  };

  class TypedRVAX86 : public TypedRVA {
   public:
    explicit TypedRVAX86(RVA rva) : TypedRVA(rva) {
    }

    virtual CheckBool ComputeRelativeTarget(const uint8* op_pointer) {
      set_relative_target(Read32LittleEndian(op_pointer) + 4);
      return true;
    }

    CheckBool EmitInstruction(AssemblyProgram* program,
                              RVA64 target_rva) {
      return program->EmitRel32(program->FindOrMakeRel32Label(target_rva));
    }
 };

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

  const uint8 *SectionBody(int id) const {
    return OffsetToPointer(SectionHeader(id)->sh_offset);
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


  CheckBool RVAToFileOffset64(Elf64_Addr addr, size_t* result) const;
  CheckBool RVAToFileOffset(Elf32_Addr addr, size_t* result) const;
  CheckBool RVAsToOffsets(ScopedVector<TypedRVA>* rvas);
  CheckBool RVAsToOffsets(ScopedVector<TypedRVA64>* rvas);

  Elf64_Phdr *program_header_table_;
  Elf64_Half program_header_table_size_;

  Elf64_Ehdr *header_;

  CheckBool ParseProgbitsSection(AssemblyProgram* program,
                                 ScopedVector<TypedRVA>::iterator* current_rel,
                                 ScopedVector<TypedRVA>::iterator end_rel,
                                 const Elf64_Shdr *section_header);
  CheckBool ParseFile(AssemblyProgram* target) WARN_UNUSED_RESULT;

  CheckBool ParseRelocs() WARN_UNUSED_RESULT;

  ScopedVector<TypedRVA64> rel64_locations_;

  ScopedVector<TypedRVA> rel32_locations_;

  DISALLOW_COPY_AND_ASSIGN(DisassemblerElf64X86_64);
};

}  // namespace courgette

#endif  // COURGETTE_DISASSEMBLER_ELF_64_H_
