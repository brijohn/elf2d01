#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#ifndef S_IWGRP
#define S_IWGRP 0
#endif

#ifndef S_IRGRP
#define S_IRGRP 0
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define PERMS S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP

#define EI_NIDENT       16 
typedef struct {
	unsigned char   e_ident[EI_NIDENT];
	uint16_t        e_type;
	uint16_t        e_machine;
	uint32_t        e_version;
	uint32_t        e_entry;
	uint32_t        e_phoff;
	uint32_t        e_shoff;
	uint32_t        e_flags;
	uint16_t        e_ehsize;
	uint16_t        e_phentsize;
	uint16_t        e_phnum;
	uint16_t        e_shentsize;
	uint16_t        e_shnum;
	uint16_t        e_shstrndx;
} Elf32_Ehdr;

#define EI_CLASS        4
#define EI_DATA         5
#define EI_VERSION      6
#define EI_PAD          7
#define EI_NIDENT       16

#define ELFCLASS32      1
#define ELFDATA2MSB     2
#define EV_CURRENT      1

#define ET_EXEC         2
#define EM_SH          42

typedef struct {
	uint32_t        p_type;
	uint32_t        p_offset;
	uint32_t        p_vaddr;
	uint32_t        p_paddr;
	uint32_t        p_filesz;
	uint32_t        p_memsz;
	uint32_t        p_flags;
	uint32_t        p_align;
} Elf32_Phdr;

#define PT_LOAD 1
#define PF_R    4
#define PF_W    2
#define PF_X    1

typedef struct {
	FILE * elf;
	uint32_t elf_textoff;
	uint32_t elf_textsz;
	uint32_t elf_dataoff;
	uint32_t elf_datasz;
	uint32_t elf_bsssz;
} Elf2D01;

static unsigned int size_header = 128;
static unsigned char header[] __attribute__((aligned(16))) = {
	0x43, 0x41, 0x53, 0x49, 0x4f, 0x44, 0x49, 0x43, 0x50, 0x4c, 0x55, 0x47, 0x49, 0x4e, 0x31, 0x30, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x30, 0x30, 0x30, 0x70, 0x00, 0x00, 0x00, 
	0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
};

#if BYTE_ORDER == BIG_ENDIAN
#define swap32(x) (x)
#define swap16(x) (x)
#else
static inline uint32_t swap32(uint32_t *v)
{
	return  (*v = ((*v >> 24) |
		((*v >> 8)  & 0x0000FF00) |
		((*v << 8)  & 0x00FF0000) |
		(*v << 24)));
}
static inline uint16_t swap16(uint16_t *v)
{
	return (*v = ((*v >> 8) | (*v << 8)));
}
#endif

#define die(x) { fprintf(stderr, x "\n"); exit(1); }
#define perrordie(x) { perror(x); exit(1); }
void ferrordie(FILE *f, const char *str)
{
	if(ferror(f)) {
		fprintf(stderr, "Error while ");
		perrordie(str);
	} else if(feof(f)) {
		fprintf(stderr, "EOF while %s\n", str);
		exit(1);
	} else {
		fprintf(stderr, "Unknown error while %s\n", str);
		exit(1);
	}
}


void read_elf_header(FILE *fp, Elf32_Ehdr *ehdr)
{
	int read;
	if(fseek(fp, 0, SEEK_SET) < 0)
		ferrordie(fp, "reading ELF header");
	read = fread(ehdr, sizeof(Elf32_Ehdr), 1, fp);
	if(read != 1)
		ferrordie(fp, "reading ELF header");
	swap16(&ehdr->e_type);
	swap16(&ehdr->e_machine);
	swap32(&ehdr->e_version);
	swap32(&ehdr->e_entry);
	swap32(&ehdr->e_phoff);
	swap32(&ehdr->e_shoff);
	swap32(&ehdr->e_flags);
	swap16(&ehdr->e_ehsize);
	swap16(&ehdr->e_phentsize);
	swap16(&ehdr->e_phnum);
	swap16(&ehdr->e_shentsize);
	swap16(&ehdr->e_shnum);
	swap16(&ehdr->e_shstrndx);
}

void read_program_header(FILE* fp, Elf32_Phdr * phdr, size_t offset)
{
	int read;
	if(fseek(fp, offset, SEEK_SET) < 0)
		ferrordie(fp, "reading ELF program headers");
	read = fread(phdr, sizeof(Elf32_Phdr), 1, fp);
	if(read != 1)
		ferrordie(fp, "reading ELF program headers");
	swap32(&phdr->p_type);
	swap32(&phdr->p_offset);
	swap32(&phdr->p_vaddr);
	swap32(&phdr->p_paddr);
	swap32(&phdr->p_filesz);
	swap32(&phdr->p_memsz);
	swap32(&phdr->p_flags);
	swap32(&phdr->p_align);
}

void parse_elf(const char * filename, Elf2D01 *d01)
{
	int i;
	Elf32_Ehdr ehdr;
	Elf32_Phdr * phdrs;
	d01->elf = fopen(filename, "rb");
	if(!d01->elf)
		perrordie("Could not open ELF file");
	read_elf_header(d01->elf, &ehdr);

	if(memcmp(&ehdr.e_ident[0], "\177ELF", 4))
		die("Invalid ELF header");
	if(ehdr.e_ident[EI_CLASS] != ELFCLASS32)
		die("Invalid ELF class");
	if(ehdr.e_ident[EI_DATA] != ELFDATA2MSB)
		die("Invalid ELF byte order");
	if(ehdr.e_ident[EI_VERSION] != EV_CURRENT)
		die("Invalid ELF ident version");
	if(ehdr.e_version != EV_CURRENT)
		die("Invalid ELF version");
	if(ehdr.e_type != ET_EXEC)
		die("ELF is not an executable");
	if(ehdr.e_machine != EM_SH)
		die("Machine is not SuperH");
	if(!ehdr.e_entry)
		die("ELF has no entrypoint");
	
	if (!ehdr.e_phnum || !ehdr.e_phoff)
		die("ELF has no program headers");

	phdrs = malloc(ehdr.e_phnum * sizeof(Elf32_Phdr));
	for (i = 0; i < ehdr.e_phnum; ++i) {
		read_program_header(d01->elf, &phdrs[i], ehdr.e_phoff + (i * sizeof(Elf32_Phdr)));
		if (phdrs[i].p_type ==	PT_LOAD) {
			if (phdrs[i].p_flags & PF_X) {
				fprintf(stderr, "Located TEXT section at 0x%08x -> 0x%08x\n",
					phdrs[i].p_offset, phdrs[i].p_offset + phdrs[i].p_filesz);
				if (phdrs[i].p_filesz != phdrs[i].p_memsz)
					die("filesize != memsize in TEXT segment");
				if (d01->elf_textoff)
					die("More then one TEXT section found");
				d01->elf_textoff = phdrs[i].p_offset;
				d01->elf_textsz = phdrs[i].p_filesz;
			} else {
				if (phdrs[i].p_filesz != 0) {
					fprintf(stderr, "Located DATA section at 0x%08x -> 0x%08x\n",
						phdrs[i].p_offset, phdrs[i].p_offset + phdrs[i].p_filesz);
					if (phdrs[i].p_filesz > phdrs[i].p_memsz)
						die("filesize > memsize in DATA segment");
					if (d01->elf_dataoff)
						die("More then one DATA section found");
					d01->elf_dataoff = phdrs[i].p_offset;
					d01->elf_datasz = phdrs[i].p_filesz;
				} else {
					fprintf(stderr, "Located BSS section at 0x%08x -> 0x%08x\n",
						phdrs[i].p_offset, phdrs[i].p_offset + phdrs[i].p_filesz);
					d01->elf_bsssz += phdrs[i].p_memsz;
				}
			}
		}
	}
}

void copy_section(FILE *dst, FILE *src, uint32_t src_off, uint32_t size)
{
	int read, write;
	char * buffer;
	if (fseek(src, src_off, SEEK_SET) < 0)
		ferrordie(src, "reading ELF section");
	buffer = malloc(size);
	read = fread(buffer, 1, size, src);
	if (read != size)
		ferrordie(src, "reading ELF section");
	write = fwrite(buffer, 1, size, dst);
	if (write != size)
		ferrordie(dst, "writing ELF section");
	free(buffer);
}

static struct option arg_opts[] = 
{
	{"help", no_argument, NULL, 'h'},
	{"module", required_argument, NULL, 'm'},
	{ NULL, 0, NULL, 0 }
};

void print_help()
{
	fprintf(stderr, "Usage: elf2d01 [-h] [-m name] infile.elf outfile.d01\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "-h, --help           : Help\n");
	fprintf(stderr, "-m, --module         : Set module name (default: cus000)\n");
}


void elf2d01(const char *input, const char *output, char * mod_name)
{
	int write;
	Elf2D01 convert;
	FILE *d01;
	memset(&convert, 0, sizeof(Elf2D01));
	fprintf(stderr, "Reading ELF file %s...\n", input);
	parse_elf(input, &convert);

	if (convert.elf_textsz + convert.elf_datasz > 0x20000)
		fprintf(stderr, "Warning: TEXT + DATA exceeds 128k limit\n");
	if (convert.elf_bsssz + convert.elf_datasz > 0x8000)
		fprintf(stderr, "Warning: DATA + BSS exceeds 32k limit\n");

	fprintf(stderr, "Writing D01 file %s...\n", output);
	d01 = fopen(output, "wb");
	if(!d01)
		perrordie("Could not open ELF file");
	fprintf(stderr, "Writing D01 header...\n");
	memcpy(header+16, mod_name, MIN(strlen(mod_name), 6));
	write = fwrite(header, size_header, 1, d01);
	if (write != 1)
		ferrordie(d01, "writing D01 header");

	fprintf(stderr, "Copying TEXT section...\n");
	copy_section(d01, convert.elf, convert.elf_textoff, convert.elf_textsz);
	fprintf(stderr, "Copying DATA section...\n");
	copy_section(d01, convert.elf, convert.elf_dataoff, convert.elf_datasz);
}

int main(int argc, char **argv)
{
	char *mod_name = "cus000";
	int ch;

	ch = getopt_long(argc, argv, "hm:", arg_opts, NULL);
	while(ch != -1) {
		switch(ch) {
		case 'h':
			print_help();
			exit(1);
		case 'm':
			if (optarg)
				mod_name = optarg;
		}
		ch = getopt_long(argc, argv, "hm:", arg_opts, NULL);
	}

	argc -= optind;
	argv += optind;
	if(argc < 2)
	{
		print_help();
		exit(1);
	}

	elf2d01(argv[0], argv[1], mod_name);
	
	return 0;
}

