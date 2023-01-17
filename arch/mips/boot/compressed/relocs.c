/*
 * Copyright (C) 2015 MontaVista Software, Inc.
 *
 * Adapted for MIPS: Silesh C V <svellattu@mvista.com>
 *
 * Based on x86 relocs tool.
 *
 * relocs does two things:
 *
 * o Extract needed relocations from vmlinux and organize the data into a
 *   form usable during decompression.
 * o Find out the size of compressed/vmlinux.bin and write it into a header
 *   where decompress.c can find it.
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <elf.h>
#include <errno.h>
#include <byteswap.h>
#include <sys/stat.h>

#define R_MIPS_NONE             0
#define R_MIPS_32               2
#define R_MIPS_26               4
#define R_MIPS_HI16             5
#define R_MIPS_LO16             6
#define R_MIPS_PC16             10
#define R_MIPS_64               18

#define ELF_BITS		64
#define	ELF_MACHINE_NAME	"MIPS64"
#define ELF_CLASS		ELFCLASS64

#define ElfW(type)              _ElfW(ELF_BITS, type)
#define _ElfW(bits, type)       __ElfW(bits, type)
#define __ElfW(bits, type)      Elf##bits##_##type

#define Elf_Addr                ElfW(Addr)
#define Elf_Ehdr                ElfW(Ehdr)
#define Elf_Phdr                ElfW(Phdr)
#define Elf_Shdr                ElfW(Shdr)
#define Elf_Sym                 ElfW(Sym)
#define Elf_Rela		ElfW(Rela)

#if __BYTE_ORDER == __BIG_ENDIAN
#define le16_to_cpu(val) (val)
#define le32_to_cpu(val) (val)
#define le64_to_cpu(val) (val)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define le16_to_cpu(val) bswap_16(val)
#define le32_to_cpu(val) bswap_32(val)
#define le64_to_cpu(val) bswap_64(val)
#endif

static uint16_t elf16_to_cpu(uint16_t val)
{
	return le16_to_cpu(val);
}

static uint32_t elf32_to_cpu(uint32_t val)
{
	return le32_to_cpu(val);
}

#define elf_half_to_cpu(x)      elf16_to_cpu(x)
#define elf_word_to_cpu(x)      elf32_to_cpu(x)

#if ELF_BITS == 64
static uint64_t elf64_to_cpu(uint64_t val)
{
	return le64_to_cpu(val);
}
#define elf_addr_to_cpu(x)      elf64_to_cpu(x)
#define elf_off_to_cpu(x)       elf64_to_cpu(x)
#define elf_xword_to_cpu(x)     elf64_to_cpu(x)
#else
#define elf_addr_to_cpu(x)      elf32_to_cpu(x)
#define elf_off_to_cpu(x)       elf32_to_cpu(x)
#define elf_xword_to_cpu(x)     elf32_to_cpu(x)
#endif

void die(char *fmt, ...);
void read_ehdr(FILE *fp);
void process(FILE *fp);

FILE *fo;

static Elf_Ehdr ehdr;
static Elf_Phdr *phdr;

struct section {
	Elf_Shdr       shdr;
	struct section *link;
	Elf_Sym        *symtab;
	Elf_Rela       *reltab;
	char           *strtab;
};

static struct section *secs;

void die(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

static void usage(void)
{
	die("relocs <vmlinux>\n");
}

static void add_reloc(ElfW(Addr) offset, int rel_type)
{
	unsigned long long be_offset;
	unsigned int be_rel_type;

	be_offset =  bswap_64(offset);
	be_rel_type = bswap_32(rel_type);

	fwrite(&be_offset, 8, 1, fo);
	fwrite(&be_rel_type, 4, 1, fo);
}

static void emit_relocs(void)
{
	unsigned int i;
	unsigned long long end_of_relocs = 0x0;

	/* Walk through the relocations */
	for (i = 0; i < ehdr.e_shnum; i++) {
		Elf_Sym *sh_symtab;
		struct section *sec_applies, *sec_symtab;
		unsigned int j;
		struct section *sec = &secs[i];

		if (sec->shdr.sh_type != SHT_RELA)
			continue;

		sec_symtab  = sec->link;
		sec_applies = &secs[sec->shdr.sh_info];
		if (!(sec_applies->shdr.sh_flags & SHF_ALLOC))
			continue;

		sh_symtab = sec_symtab->symtab;

		for (j = 0; j < sec->shdr.sh_size/sizeof(Elf_Rela); j++) {
			Elf_Rela *rel = &sec->reltab[j];
			Elf_Sym *sym = &sh_symtab[ELF64_R_SYM(rel->r_info)];
			/* We should not be relocating __attribute__((weak)) symbols which have not
			 * been overridden
			 */
			if (((ELF64_ST_BIND(sym->st_info)) == STB_WEAK) && ((ELF64_ST_TYPE(sym->st_info)) == STT_NOTYPE))
				continue;
			unsigned r_type = ELF64_R_TYPE(rel->r_info);
			ElfW(Addr) offset = rel->r_offset;
			switch (r_type) {
			case R_MIPS_32:   /*Have not found this reloc type in a loadable section*/
			case R_MIPS_NONE:
			case R_MIPS_PC16: /*Nothing to do for both these*/
				break;
			case R_MIPS_HI16:
			case R_MIPS_LO16:
			case R_MIPS_64:
			case R_MIPS_26:
				add_reloc(offset, r_type);
				break;
			default:
				printf("Unknown relocation type\n");
				break;

			}
		}
	}
	fwrite(&end_of_relocs, 8, 1, fo); /*write 0 to denote end of relocations*/
}

static void read_relocs(FILE *fp)
{
	unsigned int i, j;

	for (i = 0; i < ehdr.e_shnum; i++) {
		struct section *sec = &secs[i];
		if (sec->shdr.sh_type != SHT_RELA)
			continue;

		sec->reltab = malloc(sec->shdr.sh_size);
		if (!sec->reltab) {
			die("malloc of %d bytes for relocs failed\n",
				sec->shdr.sh_size);
		}
		if (fseek(fp, sec->shdr.sh_offset, SEEK_SET) < 0) {
			die("Seek to %d failed: %s\n",
				sec->shdr.sh_offset, strerror(errno));
		}
		if (fread(sec->reltab, 1, sec->shdr.sh_size, fp)
			!= sec->shdr.sh_size) {
			die("Cannot read symbol table: %s\n",
				strerror(errno));
		}

		for (j = 0; j < sec->shdr.sh_size/sizeof(Elf_Rela); j++) {
			Elf_Rela *rel = &sec->reltab[j];
			rel->r_offset = elf_addr_to_cpu(rel->r_offset);
			rel->r_info   = elf_xword_to_cpu(rel->r_info);
			rel->r_addend = elf_xword_to_cpu(rel->r_addend);
		}
	}
}

static void read_symtabs(FILE *fp)
{
	unsigned int i, j;

	for (i = 0; i < ehdr.e_shnum; i++) {
		struct section *sec = &secs[i];
		if (sec->shdr.sh_type != SHT_SYMTAB)
			continue;

		sec->symtab = malloc(sec->shdr.sh_size);
		if (!sec->symtab) {
			die("malloc of %d bytes for symtab failed\n",
				sec->shdr.sh_size);
		}
		if (fseek(fp, sec->shdr.sh_offset, SEEK_SET) < 0) {
			die("Seek to %d failed: %s\n",
				sec->shdr.sh_offset, strerror(errno));
		}
		if (fread(sec->symtab, 1, sec->shdr.sh_size, fp)
			!= sec->shdr.sh_size) {
			die("Cannot read symbol table: %s\n",
				strerror(errno));
		}
		for (j = 0; j < sec->shdr.sh_size/sizeof(Elf_Sym); j++) {
			Elf_Sym *sym = &sec->symtab[j];
			sym->st_name  = elf_word_to_cpu(sym->st_name);
			sym->st_value = elf_addr_to_cpu(sym->st_value);
			sym->st_size  = elf_xword_to_cpu(sym->st_size);
			sym->st_shndx = elf_half_to_cpu(sym->st_shndx);
		}
	}
}

static void read_strtabs(FILE *fp)
{
	unsigned int i;
	for (i = 0; i < ehdr.e_shnum; i++) {
		struct section *sec = &secs[i];
		if (sec->shdr.sh_type != SHT_STRTAB)
			continue;
		sec->strtab = malloc(sec->shdr.sh_size);
		if (!sec->strtab) {
			die("malloc of %d bytes for strtab failed\n",
				sec->shdr.sh_size);
		}
		if (fseek(fp, sec->shdr.sh_offset, SEEK_SET) < 0) {
			die("Seek to %d failed: %s\n",
				sec->shdr.sh_offset, strerror(errno));
		}
		if (fread(sec->strtab, 1, sec->shdr.sh_size, fp)
			!= sec->shdr.sh_size) {
			die("Cannot read symbol table: %s\n",
			strerror(errno));
		}
	}
}

static void read_shdrs(FILE *fp)
{
	unsigned int i;
	Elf_Shdr shdr;

	secs = calloc(ehdr.e_shnum, sizeof(struct section));
	if (!secs) {
		die("Unable to allocate %d section headers\n",
			ehdr.e_shnum);
	}
	if (fseek(fp, ehdr.e_shoff, SEEK_SET) < 0) {
		die("Seek to %d failed: %s\n",
			ehdr.e_shoff, strerror(errno));
	}
	for (i = 0; i < ehdr.e_shnum; i++) {
		struct section *sec = &secs[i];
		if (fread(&shdr, sizeof(shdr), 1, fp) != 1)
			die("Cannot read ELF section headers %d/%d: %s\n",
				i, ehdr.e_shnum, strerror(errno));
		sec->shdr.sh_name      = elf_word_to_cpu(shdr.sh_name);
		sec->shdr.sh_type      = elf_word_to_cpu(shdr.sh_type);
		sec->shdr.sh_flags     = elf_xword_to_cpu(shdr.sh_flags);
		sec->shdr.sh_addr      = elf_addr_to_cpu(shdr.sh_addr);
		sec->shdr.sh_offset    = elf_off_to_cpu(shdr.sh_offset);
		sec->shdr.sh_size      = elf_xword_to_cpu(shdr.sh_size);
		sec->shdr.sh_link      = elf_word_to_cpu(shdr.sh_link);
		sec->shdr.sh_info      = elf_word_to_cpu(shdr.sh_info);
		sec->shdr.sh_addralign = elf_xword_to_cpu(shdr.sh_addralign);
		sec->shdr.sh_entsize   = elf_xword_to_cpu(shdr.sh_entsize);
		if (sec->shdr.sh_link < ehdr.e_shnum)
			sec->link = &secs[sec->shdr.sh_link];
	}
}

static void read_phdrs(FILE *fp)
{
	unsigned int i;

	phdr = calloc(ehdr.e_phnum, sizeof(Elf_Phdr));
	if (!phdr) {
		die("Unable to allocate %d program headers\n",
			ehdr.e_phnum);
	}
	if (fseek(fp, ehdr.e_phoff, SEEK_SET) < 0) {
		die("Seek to %d failed: %s\n",
			ehdr.e_phoff, strerror(errno));
	}
	if (fread(phdr, sizeof(*phdr), ehdr.e_phnum, fp) != ehdr.e_phnum) {
		die("Cannot read ELF program headers: %s\n",
			strerror(errno));
	}
	for (i = 0; i < ehdr.e_phnum; i++) {
		phdr[i].p_type      = elf_word_to_cpu(phdr[i].p_type);
		phdr[i].p_offset    = elf_off_to_cpu(phdr[i].p_offset);
		phdr[i].p_vaddr     = elf_addr_to_cpu(phdr[i].p_vaddr);
		phdr[i].p_paddr     = elf_addr_to_cpu(phdr[i].p_paddr);
		phdr[i].p_filesz    = elf_word_to_cpu(phdr[i].p_filesz);
		phdr[i].p_memsz     = elf_word_to_cpu(phdr[i].p_memsz);
		phdr[i].p_flags     = elf_word_to_cpu(phdr[i].p_flags);
		phdr[i].p_align     = elf_word_to_cpu(phdr[i].p_align);
	}
}

void read_ehdr(FILE *fp)
{
	if (fread(&ehdr, sizeof(ehdr), 1, fp) != 1) {
		die("Cannot read ELF header: %s\n",
			strerror(errno));
	}
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
		die("No ELF magic\n");

	if (ehdr.e_ident[EI_CLASS] != ELF_CLASS)
		die("Not a %d bit executable\n", ELF_BITS);

	if (ehdr.e_ident[EI_DATA] != ELFDATA2MSB)
		die("Not a MSB ELF executable\n");

	if (ehdr.e_ident[EI_VERSION] != EV_CURRENT)
		die("Unknown ELF version\n");

	/* Convert the fields to native endian */
	ehdr.e_type      = elf_half_to_cpu(ehdr.e_type);
	ehdr.e_machine   = elf_half_to_cpu(ehdr.e_machine);
	ehdr.e_version   = elf_word_to_cpu(ehdr.e_version);
	ehdr.e_entry     = elf_addr_to_cpu(ehdr.e_entry);
	ehdr.e_phoff     = elf_off_to_cpu(ehdr.e_phoff);
	ehdr.e_shoff     = elf_off_to_cpu(ehdr.e_shoff);
	ehdr.e_flags     = elf_word_to_cpu(ehdr.e_flags);
	ehdr.e_ehsize    = elf_half_to_cpu(ehdr.e_ehsize);
	ehdr.e_phentsize = elf_half_to_cpu(ehdr.e_phentsize);
	ehdr.e_phnum     = elf_half_to_cpu(ehdr.e_phnum);
	ehdr.e_shentsize = elf_half_to_cpu(ehdr.e_shentsize);
	ehdr.e_shnum     = elf_half_to_cpu(ehdr.e_shnum);
	ehdr.e_shstrndx  = elf_half_to_cpu(ehdr.e_shstrndx);

	if ((ehdr.e_type != ET_EXEC) && (ehdr.e_type != ET_DYN))
		die("Unsupported ELF header type\n");

	if (ehdr.e_machine != EM_MIPS)
		die("Not for %s\n", ELF_MACHINE_NAME);

	if (ehdr.e_version != EV_CURRENT)
		die("Unknown ELF version\n");

	if (ehdr.e_ehsize != sizeof(Elf_Ehdr))
		die("Bad Elf header size\n");

	if (ehdr.e_phentsize != sizeof(Elf_Phdr))
		die("Bad program header entry\n");

	if (ehdr.e_shentsize != sizeof(Elf_Shdr))
		die("Bad section header entry\n");

	if (ehdr.e_shstrndx >= ehdr.e_shnum)
		die("String table index out of bounds\n");

}

void process(FILE *fp)
{
	read_ehdr(fp);
	read_phdrs(fp);
	read_shdrs(fp);
	read_strtabs(fp);
	read_symtabs(fp);
	read_relocs(fp);
	emit_relocs();
}

char *header_name = "arch/mips/boot/compressed/vmlinux_bin_size.h";
char *binfile = "arch/mips/boot/compressed/vmlinux.bin";

int main(int argc, char *argv[])
{
	FILE *fp, *fheader;
	char *fname;
	struct stat sb;


	if (argc != 2) {
		usage();
		exit(1);
	}

	/* Find out the size of vmlinux.bin and write it out, decompress.c needs this
	 * during relocation processing*/

	fheader = fopen(header_name, "w");

	if (stat(binfile, &sb) == -1)
		die("Stat Failed");

	fprintf(fheader, "#define VMLINUX_BIN_SIZE 0x%llx\n", (unsigned long long)sb.st_size);

	fclose(fheader);

	fo = stdout;

	fname = argv[1];

	fp = fopen(fname, "r");

	if (!fp) {
		printf("Cannot open %s\n", fname);
		exit(1);
	}

	process(fp);
	fclose(fp);
	return 0;
}
