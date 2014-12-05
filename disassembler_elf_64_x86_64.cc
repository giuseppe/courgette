// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "courgette/disassembler_elf_64_x86_64.h"

#include <algorithm>
#include <string>
#include <vector>

#include "base/basictypes.h"
#include "base/logging.h"
#include "base/memory/scoped_vector.h"

#include "courgette/assembly_program.h"
#include "courgette/courgette.h"
#include "courgette/encoded_program.h"

namespace courgette {

DisassemblerElf64X86_64::DisassemblerElf64X86_64(const void* start, size_t length)
  : Disassembler(start, length),
    header_(NULL),
    section_header_table_(NULL),
    section_header_table_size_(0),
    program_header_table_(NULL),
    program_header_table_size_(0) {
}

bool DisassemblerElf64X86_64::ParseHeader() {
  if (length() < sizeof(Elf64_Ehdr))
    return Bad("Too small");

  header_ = (Elf64_Ehdr *)start();

  // Have magic for elf header?
  if (header_->e_ident[0] != 0x7f ||
      header_->e_ident[1] != 'E' ||
      header_->e_ident[2] != 'L' ||
      header_->e_ident[3] != 'F')
    return Bad("No Magic Number");

  if (header_->e_type != ET_EXEC &&
      header_->e_type != ET_DYN)
    return Bad("Not an executable file or shared library");

  if (header_->e_machine != ElfEM())
    return Bad("Not a supported architecture");

  if (header_->e_version != 1)
    return Bad("Unknown file version");

  if (header_->e_shoff >= length())
    return Bad("Out of bounds section header table offset");

  section_header_table_ = (Elf64_Shdr *)OffsetToPointer(header_->e_shoff);
  section_header_table_size_ = header_->e_shnum;

  if ((header_->e_shoff + header_->e_shnum ) >= length())
    return Bad("Out of bounds section header table");

  if (header_->e_phoff >= length())
    return Bad("Out of bounds program header table offset");

  program_header_table_ = (Elf64_Phdr *)OffsetToPointer(header_->e_phoff);
  program_header_table_size_ = header_->e_phnum;

  ReduceLength(DiscoverLength());

  return Good();
}

uint32 DisassemblerElf64X86_64::DiscoverLength() {
  uint64 result = 0;

  // Find the end of the last section
  for (int section_id = 0; section_id < SectionHeaderCount(); section_id++) {
    const Elf64_Shdr *section_header = SectionHeader(section_id);

    if (section_header->sh_type == SHT_NOBITS)
      continue;

    uint64 section_end = section_header->sh_offset + section_header->sh_size;

    if (section_end > result)
      result = section_end;
  }

  // Find the end of the last segment
  for (int i = 0; i < ProgramSegmentHeaderCount(); i++) {
    const Elf64_Phdr *segment_header = ProgramSegmentHeader(i);

    uint64 segment_end = segment_header->p_offset + segment_header->p_filesz;

    if (segment_end > result)
      result = segment_end;
  }

  uint64 section_table_end = header_->e_shoff +
                             (header_->e_shnum * sizeof(Elf64_Shdr));
  if (section_table_end > result)
    result = section_table_end;

  uint64 segment_table_end = header_->e_phoff +
                             (header_->e_phnum * sizeof(Elf64_Phdr));
  if (segment_table_end > result)
    result = segment_table_end;

  return result;
}

bool DisassemblerElf64X86_64::Disassemble(AssemblyProgram* target) {
  if (!ok())
    return false;

  // The Image Base is always 0 for ELF Executables
  target->set_image_base(0);

  if (!ParseRelocs())
    return false;

  if (!ParseRel32RelocsFromSections())
    return false;

  if (!ParseFile(target))
    return false;

  target->DefaultAssignIndexes();

  return true;
}

CheckBool DisassemblerElf64X86_64::ParseProgbitsSection(AssemblyProgram* program,
                                                        ScopedVector<TypedRVA>::iterator* current_rel,
                                                        ScopedVector<TypedRVA>::iterator end_rel,
                                                        const Elf64_Shdr *section_header) {

  // Walk all the bytes in the file, whether or not in a section.
  size_t file_offset = section_header->sh_offset;
  size_t section_end = section_header->sh_offset + section_header->sh_size;

  Elf64_Addr origin = section_header->sh_addr;
  size_t origin_offset = section_header->sh_offset;

  if (!program->EmitOriginInstruction(origin))
    return false;

  while (file_offset < section_end) {

    while (*current_rel != end_rel &&
           file_offset > (**current_rel)->get_offset()) {
      (*current_rel)++;
    }

    size_t next_relocation = section_end;

    if (*current_rel != end_rel &&
        next_relocation > ((**current_rel)->get_offset() + 4))
      next_relocation = (**current_rel)->get_offset();

    if (next_relocation > file_offset) {
      if (!ParseSimpleRegion(file_offset, next_relocation, program))
        return false;

      file_offset = next_relocation;
      continue;
    }

    if (*current_rel != end_rel &&
        file_offset == (**current_rel)->get_offset()) {
      uint32 relative_target = (**current_rel)->relative_target();
      RVA target_rva = (RVA)(origin + (file_offset - origin_offset) +
                             relative_target);
      if (!((TypedRVAX86*) **current_rel)->EmitInstruction(program, target_rva))
        return false;
      file_offset += (**current_rel)->op_size();
      (*current_rel)++;
      continue;
    }
  }

  // Rest of the section (if any)
  return ParseSimpleRegion(file_offset, section_end, program);
}

CheckBool DisassemblerElf64X86_64::ParseSimpleRegion(
    size_t start_file_offset,
    size_t end_file_offset,
    AssemblyProgram* program) {
  // Callers don't guarantee start < end
  if (start_file_offset >= end_file_offset) return true;

  const size_t len = end_file_offset - start_file_offset;

  if (!program->EmitBytesInstruction(OffsetToPointer(start_file_offset), len))
    return false;

  return true;
}

CheckBool DisassemblerElf64X86_64::RVAToFileOffset64(Elf64_Addr addr,
                                                     size_t* result) const {
  for (int i = 0; i < ProgramSegmentHeaderCount(); i++) {
    Elf64_Addr begin = ProgramSegmentMemoryBegin(i);
    Elf64_Addr end = begin + ProgramSegmentMemorySize(i);
    if (addr >= begin  && addr < end) {
      Elf64_Addr offset = addr - begin;

      if (offset < ProgramSegmentFileSize(i)) {
        *result = ProgramSegmentFileOffset(i) + offset;
        return true;
      }
    }
  }
  return false;
}

CheckBool DisassemblerElf64X86_64::RVAsToOffsets(ScopedVector<TypedRVA64>* rvas) {
  for (ScopedVector<TypedRVA64>::iterator rva = rvas->begin();
       rva != rvas->end();
       rva++) {

    size_t offset;

    if (!RVAToFileOffset64((*rva)->rva(), &offset))
      return false;

    (*rva)->set_offset(offset);
  }

  return true;
}

CheckBool DisassemblerElf64X86_64::RVAToFileOffset(Elf32_Addr addr,
                                                   size_t* result) const {
  for (int i = 0; i < ProgramSegmentHeaderCount(); i++) {
    Elf32_Addr begin = ProgramSegmentMemoryBegin(i);
    Elf32_Addr end = begin + ProgramSegmentMemorySize(i);
    if (addr >= begin  && addr < end) {
      Elf32_Addr offset = addr - begin;

      if (offset < ProgramSegmentFileSize(i)) {
        *result = ProgramSegmentFileOffset(i) + offset;
        return true;
      }
    }
  }
  return false;
}

CheckBool DisassemblerElf64X86_64::RVAsToOffsets(ScopedVector<TypedRVA>* rvas) {
  for (ScopedVector<TypedRVA>::iterator rva = rvas->begin();
       rva != rvas->end();
       rva++) {

    size_t offset;

    if (!RVAToFileOffset((*rva)->rva(), &offset))
      return false;

    (*rva)->set_offset(offset);
  }

  return true;
}

CheckBool DisassemblerElf64X86_64::ParseRelocationSection(const Elf64_Shdr *section_header,
                                                          AssemblyProgram* program) {

  size_t origin_offset = section_header->sh_offset;
  Elf64_Addr origin = section_header->sh_addr;

  Elf64_Rela *relocs_table;
  int relocs_table_count;

  if (!program->EmitOriginInstruction(origin))
    return false;

  if (section_header->sh_type != SHT_RELA) {

    if (!program->EmitBytesInstruction((const uint8*) section_header,
                                       (size_t) section_header->sh_size))
      return false;
  }

  relocs_table = (Elf64_Rela *) OffsetToPointer(section_header->sh_offset);
  relocs_table_count = section_header->sh_size / section_header->sh_entsize;

  // Loop through relocation objects in the relocation section
  for (int rel_id = 0; rel_id < relocs_table_count; rel_id++) {

    int type = relocs_table[rel_id].r_info & 0xffffffffL;

    if (type == R_X86_64_RELATIVE) {
      uint64 offset = relocs_table[rel_id].r_offset;
      int64 addend = relocs_table[rel_id].r_addend;
      uint64 current_rva = origin + ((uint64) &relocs_table[rel_id] - (uint64) &relocs_table[0]);
      uint64 rva = offset;
      if (!program->EmitRela64(rva - current_rva, addend))
        return false;
    }
    else {
      if (!program->EmitBytesInstruction((const uint8*) &relocs_table[rel_id],
                                         (size_t) section_header->sh_entsize))
        return false;
      continue;
    }
  }

  return true;
}

CheckBool DisassemblerElf64X86_64::ParseFile(AssemblyProgram* program) {
  // Walk all the bytes in the file, whether or not in a section.
  uint32 file_offset = 0;

  if (!RVAsToOffsets(&rel64_locations_))
    return false;

  if (!RVAsToOffsets(&rel32_locations_))
    return false;

  ScopedVector<TypedRVA>::iterator current_rel = rel32_locations_.begin();
  ScopedVector<TypedRVA>::iterator end_rel = rel32_locations_.end();

  for (int section_id = 0;
       section_id < SectionHeaderCount();
       section_id++) {

    const Elf64_Shdr *section_header = SectionHeader(section_id);
    file_offset = section_header->sh_offset;

    switch (section_header->sh_type) {
    case SHT_RELA:
      if (!ParseRelocationSection(section_header, program))
        return false;
      file_offset = section_header->sh_offset + section_header->sh_size;
      break;

    case SHT_PROGBITS:
      if (!ParseSimpleRegion(file_offset,
                             section_header->sh_offset,
                             program))
        return false;
      if (!ParseProgbitsSection(program,
                                &current_rel, end_rel,
                                section_header))
        return false;
      file_offset = section_header->sh_offset + section_header->sh_size;
      break;

    default:
      if (!ParseSimpleRegion(file_offset,
                             section_header->sh_offset,
                             program))
        return false;
      file_offset = section_header->sh_offset + section_header->sh_size;
      break;
    }
  }

  // Rest of the file past the last section
  return ParseSimpleRegion(file_offset,
                           length(),
                           program);
}

CheckBool DisassemblerElf64X86_64::ParseRelocs() {
  rel64_locations_.clear();

  // Loop through sections for relocation sections
  for (int section_id = 0; section_id < SectionHeaderCount(); section_id++) {
    const Elf64_Shdr *section_header = SectionHeader(section_id);

    if (section_header->sh_type == SHT_RELA) {

      Elf64_Rela *relocs_table = (Elf64_Rela *)SectionBody(section_id);

      int relocs_table_count = section_header->sh_size /
                               section_header->sh_entsize;

      // Loop through relocation objects in the relocation section
      for (int rel_id = 0; rel_id < relocs_table_count; rel_id++) {
        int type = relocs_table[rel_id].r_info & 0xffffffffL;
        int sym_index = relocs_table[rel_id].r_info >> 32;
        if (type != R_X86_64_RELATIVE)
          continue;

        uint64 target = relocs_table[rel_id].r_addend;
        if (sym_index != 0)
          continue;

        size_t res;
        if (!RVAToFileOffset((RVA) target, &res))
          continue;

        TypedRVA64 *rva = new TypedRVA64(target);
        rel64_locations_.push_back(rva);
      }
    }
  }

  std::sort(rel64_locations_.begin(),
            rel64_locations_.end(),
            TypedRVA64::IsLessThan);

  return true;
}

CheckBool DisassemblerElf64X86_64::IsValidRVA(RVA rva) const {

  // It's valid if it's contained in any program segment
  for (int i = 0; i < ProgramSegmentHeaderCount(); i++) {
    const Elf64_Phdr *segment_header = ProgramSegmentHeader(i);

    if (segment_header->p_type != PT_LOAD)
      continue;

    Elf64_Addr begin = segment_header->p_vaddr;
    Elf64_Addr end = segment_header->p_vaddr + segment_header->p_memsz;

    if (rva >= begin && rva < end)
      return true;
  }

  return false;
}

CheckBool DisassemblerElf64X86_64::ParseRel32RelocsFromSections() {

  rel32_locations_.clear();

  // Loop through sections for relocation sections
  for (int section_id = 0;
       section_id < SectionHeaderCount();
       section_id++) {

    const Elf64_Shdr *section_header = SectionHeader(section_id);

    if (section_header->sh_type != SHT_PROGBITS)
      continue;

    if (!ParseRel32RelocsFromSection(section_header))
      return false;
  }

  std::sort(rel32_locations_.begin(),
            rel32_locations_.end(),
            TypedRVA::IsLessThan);
  return true;
}

CheckBool DisassemblerElf64X86_64::ParseRel32RelocsFromSection(
    const Elf64_Shdr* section_header) {

  uint32 start_file_offset = section_header->sh_offset;
  uint32 end_file_offset = start_file_offset + section_header->sh_size;

  const uint8* start_pointer = OffsetToPointer(start_file_offset);
  const uint8* end_pointer = OffsetToPointer(end_file_offset);

  // Quick way to convert from Pointer to RVA within a single Section is to
  // subtract 'pointer_to_rva'.
  const uint8* const adjust_pointer_to_rva = start_pointer -
                                             section_header->sh_addr;

  // Find the rel32 relocations.
  const uint8* p = start_pointer;
  while (p < end_pointer) {
    //RVA current_rva = static_cast<RVA>(p - adjust_pointer_to_rva);

    // Heuristic discovery of rel32 locations in instruction stream: are the
    // next few bytes the start of an instruction containing a rel32
    // addressing mode?
    const uint8* rel32 = NULL;

    if (p + 5 <= end_pointer) {
      if (*p == 0xE8 || *p == 0xE9) {  // jmp rel32 and call rel32
        rel32 = p + 1;
      }
    }
    if (p + 6 <= end_pointer) {
      if (*p == 0x0F  &&  (*(p+1) & 0xF0) == 0x80) {  // Jcc long form
        if (p[1] != 0x8A && p[1] != 0x8B)  // JPE/JPO unlikely
          rel32 = p + 2;
      }
    }
    if (rel32) {
      RVA rva = static_cast<RVA>(rel32 - adjust_pointer_to_rva);
      TypedRVAX86* rel32_rva = new TypedRVAX86(rva);

      if (!rel32_rva->ComputeRelativeTarget(rel32)) {
        return false;
      }

      RVA target_rva = rel32_rva->rva() + rel32_rva->relative_target();
      // To be valid, rel32 target must be within image, and within this
      // section.
      if (IsValidRVA(target_rva)) {
        //rel32_locations_.push_back(rel32_rva);
#if COURGETTE_HISTOGRAM_TARGETS
        ++rel32_target_rvas_[target_rva];
#endif
        p = rel32 + 4;
        continue;
      } else {
        delete rel32_rva;
      }
    }
    p += 1;
  }

  return true;
}

}  // namespace courgette
