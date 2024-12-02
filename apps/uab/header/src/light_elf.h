// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <elf.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <optional>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace lightElf {

constexpr auto header_ident = EI_NIDENT;
constexpr std::size_t machine_type = sizeof(void *) == 8 ? 64 : 32;

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
    unsigned char ident[header_ident]; // NOLINT
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

template<std::size_t Bit>
class Elf
{
public:
    Elf() = delete;
    Elf(const Elf &) = delete;
    Elf &operator=(const Elf &) = delete;
    Elf(Elf &&) = delete;
    Elf &operator=(Elf &&) = delete;

    ~Elf()
    {
        if (fd != -1) {
            ::close(fd);
        }
    }

    explicit Elf(const std::filesystem::path &path)
    {
        auto fd = ::open(path.c_str(), O_RDONLY);
        if (fd == -1) {
            throw std::runtime_error("failed to open " + path.string() + ": " + ::strerror(errno));
        }

        FileHeader<Bit> elfHeader;
        if (::pread(fd, &elfHeader, sizeof(elfHeader), 0) == -1) {
            ::close(fd);
            throw std::runtime_error("failed to read " + path.string() + ": " + ::strerror(errno));
        }

        if (elfHeader.ident[EI_MAG0] != ELFMAG0 || elfHeader.ident[EI_MAG1] != ELFMAG1
            || elfHeader.ident[EI_MAG2] != ELFMAG2 || elfHeader.ident[EI_MAG3] != ELFMAG3) {
            ::close(fd);
            throw std::runtime_error(path.string() + "is not an elf file");
        }

        if (elfHeader.section_header_offset == 0) {
            throw std::runtime_error("current elf does not has section header table");
        }

        auto shdrstrndx = elfHeader.section_header_string_table_index;
        if (shdrstrndx == SHN_UNDEF) {
            throw std::runtime_error("current elf does not has section header string table");
        }

        SectionHeader<Bit> shdr;
        if (shdrstrndx == SHN_XINDEX) {
            auto firstSection = elfHeader.section_header_offset;
            if (::pread(fd, &shdr, sizeof(shdr), elfHeader.section_header_offset) == -1) {
                throw std::runtime_error("failed to read initial section header of" + path.string()
                                         + ": " + ::strerror(errno));
            }

            if (shdr.link == 0) {
                throw std::runtime_error(
                  "current elf is invalid, sh_link of initial section header is 0 but e_shstrdx is"
                  + std::to_string(SHN_XINDEX));
            }

            shdrstrndx = shdr.link;
        }

        auto shdrstrtab =
          elfHeader.section_header_offset + shdrstrndx * elfHeader.section_header_entry_size;
        if (::pread(fd, &shdr, sizeof(shdr), shdrstrtab) == -1) {
            throw std::runtime_error("failed to read section header string table of" + path.string()
                                     + ": " + ::strerror(errno));
        }

        if (shdr.type != SHT_STRTAB) {
            throw std::runtime_error("the type of section header string table is invalid");
        }

        std::vector<char> rawData(shdr.size, '\0'); // NOTE: must reserve enough space before read
        if (::pread(fd, rawData.data(), shdr.size, shdr.offset) == -1) {
            throw std::runtime_error("failed to read section header string table of" + path.string()
                                     + ": " + ::strerror(errno));
        }

        auto strBegin = rawData.begin();
        auto strEnd = rawData.begin();
        while (strEnd != rawData.end()) {
            if (*strEnd != '\0') {
                ++strEnd;
                continue;
            }

            sectionNames.emplace_back(strBegin, strEnd);
            strBegin = strEnd + 1;
            strEnd = strBegin;
        }

        this->fd = fd;
        this->header = elfHeader;
    }

    const FileHeader<Bit> &fileHeader() const noexcept { return header; }

    // NOTE!!: DO NOT CLOSE
    [[nodiscard]] int underlyingFd() const noexcept { return fd; }

    [[nodiscard]] std::filesystem::path absolutePath() const
    {
        auto path = std::filesystem::path("/proc/self/fd/" + std::to_string(fd));
        return std::filesystem::read_symlink(path);
    }

    std::optional<SectionHeader<Bit>> getSectionHeader(const std::string &name) const
    {
        auto it = std::find(sectionNames.cbegin(), sectionNames.cend(), name);
        if (it == sectionNames.cend()) {
            return std::nullopt;
        }

        SectionHeader<Bit> shdr;
        auto offset = header.section_header_offset;
        for (auto index = 0; index < header.section_header_count; ++index) {
            offset += (index * header.section_header_entry_size);
            if (::pread(fd, &shdr, sizeof(shdr), offset) == -1) {
                throw std::runtime_error("failed to read section header of" + name + ": "
                                         + ::strerror(errno));
            }

            if (sectionNames[shdr.name] == name) {
                return shdr;
            }
        }

        return std::nullopt;
    }

private:
    std::vector<std::string> sectionNames;
    FileHeader<Bit> header;
    int fd{ -1 };
};

using currentElf = Elf<machine_type>;

} // namespace lightElf
