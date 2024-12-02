// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <elf.h>

#include <array>
#include <cstddef>
#include <filesystem>
#include <memory>

#include <unistd.h>

namespace lightElf {

constexpr auto header_ident = EI_NIDENT;

template<std::size_t Bit>
struct Elf_trait;

template<>
struct Elf_trait<64>
{
    using half = Elf64_Half;
    using word = Elf64_Word;
    using sword = Elf64_Sword;
    using xword = Elf64_Xword;
    using sxword = Elf64_Sxword;
    using address = Elf64_Addr;
    using offset = Elf64_Off;
    using section = Elf64_Section;
    using version_sym_info = Elf64_Versym;
};

template<>
struct Elf_trait<32>
{
    using half = Elf32_Half;
    using word = Elf32_Word;
    using sword = Elf32_Sword;
    using xword = Elf32_Xword;
    using sxword = Elf32_Sxword;
    using address = Elf32_Addr;
    using offset = Elf32_Off;
    using section = Elf32_Section;
    using version_sym_info = Elf32_Versym;
};

template<std::size_t Bit>
struct FileHeader
{
    std::array<unsigned char, header_ident> ident;
    typename Elf_trait<Bit>::half type;
    typename Elf_trait<Bit>::half machine;
    typename Elf_trait<Bit>::word version;
    typename Elf_trait<Bit>::address entry;
    typename Elf_trait<Bit>::offset program_header_offset;
    typename Elf_trait<Bit>::section section_header_offset;
    typename Elf_trait<Bit>::word flags;
    typename Elf_trait<Bit>::half header_size;
    typename Elf_trait<Bit>::half program_header_entry_size;
    typename Elf_trait<Bit>::half program_header_count;
    typename Elf_trait<Bit>::half section_header_entry_size;
    typename Elf_trait<Bit>::half section_header_count;
    typename Elf_trait<Bit>::half section_header_string_table_index;
};

template<std::size_t Bit>
struct SectionHeader
{
    typename Elf_trait<Bit>::word name;
    typename Elf_trait<Bit>::word type;
    typename Elf_trait<Bit>::xword flags;
    typename Elf_trait<Bit>::address addr;
    typename Elf_trait<Bit>::offset offset;
    typename Elf_trait<Bit>::xword size;
    typename Elf_trait<Bit>::xword link;
    typename Elf_trait<Bit>::xword info;
    typename Elf_trait<Bit>::xword addralign;
    typename Elf_trait<Bit>::xword entsize;
};

class ElfContext
{
public:
    ElfContext() = delete;
    ElfContext(const ElfContext &) = delete;
    ElfContext &operator=(const ElfContext &) = delete;

    static std::unique_ptr<ElfContext> CreateContext(const std::filesystem::path &path)
    {
        
     }

    ElfContext(ElfContext &&other) noexcept
        : fd(other.fd)
    {
        other.fd = 0;
    }

    ElfContext &operator=(ElfContext &&other) noexcept
    {
        if (this == &other) {
            return *this;
        }

        std::swap(fd, other.fd);
        return *this;
    }

    ~ElfContext()
    {
        if (fd != 0) {
            ::close(fd);
        }
    }

private:
    int fd{ 0 };
};

} // namespace lightElf
