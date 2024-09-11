#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>

#define MAX_FILES 2
#define MAX_OPTION_LEN 128

int debug_mode = 0;
int fd[MAX_FILES] = {-1, -1};
void *map_start[MAX_FILES] = {NULL, NULL};
char *file_names[MAX_FILES] = {NULL, NULL};

typedef struct {
    char *name;
    void (*func)();
} menu_option;

//Functions Declerations:
void toggle_debug_mode();
void examine_elf_file();
void print_section_names();
void print_symbols();
void check_files_for_merge();
void merge_elf_files();
void quit();

menu_option menu[] = {
    {"Toggle Debug Mode", toggle_debug_mode},
    {"Examine ELF File", examine_elf_file},
    {"Print Section Names", print_section_names},
    {"Print Symbols", print_symbols},
    {"Check Files for Merge", check_files_for_merge},
    {"Merge ELF Files", merge_elf_files},
    {"Quit", quit}
};

void toggle_debug_mode() {
    debug_mode = !debug_mode;
    printf("Debug mode %s\n", debug_mode ? "on" : "off");
}

void examine_elf_file() {
    if (fd[0] != -1 && fd[1] != -1) {
        printf("Already handling two ELF files. Cannot handle more.\n");
        return;
    }

    char filename[MAX_OPTION_LEN];
    printf("Enter ELF file name: ");
    scanf("%s", filename);

    int index = fd[0] == -1 ? 0 : 1;

    fd[index] = open(filename, O_RDONLY);
    if (fd[index] == -1) {
        perror("Error opening file");
        return;
    }

    struct stat fd_stat;
    if (fstat(fd[index], &fd_stat) != 0) {
        perror("Error fstat");
        close(fd[index]);
        fd[index] = -1;
        return;
    }

    map_start[index] = mmap(NULL, fd_stat.st_size, PROT_READ, MAP_PRIVATE, fd[index], 0);
    if (map_start[index] == MAP_FAILED) {
        perror("Error mmap");
        close(fd[index]);
        fd[index] = -1;
        return;
    }

    Elf32_Ehdr *header = (Elf32_Ehdr *)map_start[index];
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
        printf("Not an ELF file\n");
        munmap(map_start[index], fd_stat.st_size);
        close(fd[index]);
        fd[index] = -1;
        return;
    }

    file_names[index] = strdup(filename);

    printf("Magic: %c%c%c\n", header->e_ident[EI_MAG1], header->e_ident[EI_MAG2], header->e_ident[EI_MAG3]);
    printf("Data: %s\n", header->e_ident[EI_DATA] == ELFDATA2LSB ? "2's complement, little endian" : "2's complement, big endian");
    printf("Entry point address: 0x%x\n", header->e_entry);
    printf("Start of section headers: %d (bytes into file)\n", header->e_shoff);
    printf("Number of section headers: %d\n", header->e_shnum);
    printf("Size of section headers: %d (bytes)\n", header->e_shentsize);
    printf("Start of program headers: %d (bytes into file)\n", header->e_phoff);
    printf("Number of program headers: %d\n", header->e_phnum);
    printf("Size of program headers: %d (bytes)\n", header->e_phentsize);
}

void print_section_names() {
    for (int index = 0; index < MAX_FILES; index++) {
        if (fd[index] == -1) {
            printf("No ELF file currently examined at index %d\n", index);
            continue;
        }

        Elf32_Ehdr *header = (Elf32_Ehdr *)map_start[index];
        Elf32_Shdr *section_headers = (Elf32_Shdr *)(map_start[index] + header->e_shoff);
        const char *section_str_table = (const char *)(map_start[index] + section_headers[header->e_shstrndx].sh_offset);

        printf("File %s\n", file_names[index]);
        for (int i = 0; i < header->e_shnum; i++) {
            printf("[%2d] %s 0x%08x 0x%06x 0x%06x 0x%x\n",
                   i,
                   section_str_table + section_headers[i].sh_name,
                   section_headers[i].sh_addr,
                   section_headers[i].sh_offset,
                   section_headers[i].sh_size,
                   section_headers[i].sh_type);
        }
    }
}

void print_symbols() {
    for (int index = 0; index < MAX_FILES; index++) {
        if (fd[index] == -1) {
            printf("No ELF file currently examined at index %d\n", index);
            continue;
        }

        Elf32_Ehdr *header = (Elf32_Ehdr *)map_start[index];
        Elf32_Shdr *section_headers = (Elf32_Shdr *)(map_start[index] + header->e_shoff);
        const char *section_str_table = (const char *)(map_start[index] + section_headers[header->e_shstrndx].sh_offset);
        
        Elf32_Shdr *symtab = NULL;
        Elf32_Shdr *strtab = NULL;

        // Locate the symbol table and string table
        for (int i = 0; i < header->e_shnum; i++) {
            if (section_headers[i].sh_type == SHT_SYMTAB) {
                symtab = &section_headers[i];
            }
            if (section_headers[i].sh_type == SHT_STRTAB && strcmp(section_str_table + section_headers[i].sh_name, ".strtab") == 0) {
                strtab = &section_headers[i];
            }
        }

        if (!symtab || !strtab) {
            printf("No symbol table found in file %s\n", file_names[index]);
            continue;
        }

        Elf32_Sym *symbols = (Elf32_Sym *)(map_start[index] + symtab->sh_offset);
        const char *strtab_ptr = (const char *)(map_start[index] + strtab->sh_offset);

        int symbol_count = symtab->sh_size / symtab->sh_entsize;

        printf("File %s\n", file_names[index]);
        for (int i = 0; i < symbol_count; i++) {
            int section_index = symbols[i].st_shndx;
            const char *section_name = section_index == SHN_ABS ? "ABS" :
                                        section_index == SHN_COMMON ? "COMMON" :
                                        section_index == SHN_UNDEF ? "UND" :
                                        section_str_table + section_headers[section_index].sh_name;

            printf("[%2d] 0x%08x %d %s %s\n",
                   i,
                   symbols[i].st_value,
                   section_index,
                   section_name,
                   strtab_ptr + symbols[i].st_name);
        }
    }
}

void check_files_for_merge() {
    // Ensure exactly two ELF files are opened and mapped
    if (fd[0] == -1 || fd[1] == -1) {
        printf("Error: Need exactly two ELF files opened and mapped.\n");
        return;
    }

    Elf32_Ehdr *header1 = (Elf32_Ehdr *)map_start[0];
    Elf32_Ehdr *header2 = (Elf32_Ehdr *)map_start[1];

    // Ensure each file has exactly one symbol table (SHT_SYMTAB)
    int symtab_count1 = 0, symtab_count2 = 0;
    Elf32_Shdr *section_headers1 = (Elf32_Shdr *)(map_start[0] + header1->e_shoff);
    Elf32_Shdr *section_headers2 = (Elf32_Shdr *)(map_start[1] + header2->e_shoff);
    
    for (int i = 0; i < header1->e_shnum; i++) {
        if (section_headers1[i].sh_type == SHT_SYMTAB)
            symtab_count1++;
    }

    for (int i = 0; i < header2->e_shnum; i++) {
        if (section_headers2[i].sh_type == SHT_SYMTAB)
            symtab_count2++;
    }

    if (symtab_count1 != 1 || symtab_count2 != 1) {
        printf("Error: Each ELF file must have exactly one symbol table.\n");
        return;
    }

    // Locate symbol tables
    Elf32_Shdr *symtab1 = NULL, *symtab2 = NULL;
    for (int i = 0; i < header1->e_shnum; i++) {
        if (section_headers1[i].sh_type == SHT_SYMTAB)
            symtab1 = &section_headers1[i];
    }

    for (int i = 0; i < header2->e_shnum; i++) {
        if (section_headers2[i].sh_type == SHT_SYMTAB)
            symtab2 = &section_headers2[i];
    }

    if (!symtab1 || !symtab2) {
        printf("Error: Could not find symbol table in both ELF files.\n");
        return;
    }

    // Get symbol tables
    Elf32_Sym *symbols1 = (Elf32_Sym *)(map_start[0] + symtab1->sh_offset);
    Elf32_Sym *symbols2 = (Elf32_Sym *)(map_start[1] + symtab2->sh_offset);
    const char *strtab1 = (const char *)(map_start[0] + section_headers1[symtab1->sh_link].sh_offset);
    const char *strtab2 = (const char *)(map_start[1] + section_headers2[symtab2->sh_link].sh_offset);

    // Check each symbol in SYMTAB1 against SYMTAB2
    int symbol_count1 = symtab1->sh_size / symtab1->sh_entsize;
    int symbol_count2 = symtab2->sh_size / symtab2->sh_entsize;

    int error_found = 0;

    printf("Checking for merge errors:\n");

    for (int i = 1; i < symbol_count1; i++) {
        Elf32_Sym *symbol1 = &symbols1[i];
        const char *name1 = strtab1 + symbol1->st_name;

        if (ELF32_ST_TYPE(symbol1->st_info) == STT_NOTYPE) {
            // Search for symbol in SYMTAB2
            int found_undefined = 0;
            for (int j = 1; j < symbol_count2; j++) {
                Elf32_Sym *symbol2 = &symbols2[j];
                const char *name2 = strtab2 + symbol2->st_name;
                if (strcmp(name1, name2) == 0 && ELF32_ST_TYPE(symbol2->st_info) != STT_NOTYPE) {
                    found_undefined = 1;
                    break;
                }
            }
            if (!found_undefined) {
                printf("Symbol %s undefined in ELF file 2\n", name1);
                error_found = 1;
            }
        } else if (symbol1->st_shndx != SHN_UNDEF) {
            // Symbol is defined, check if it's multiply defined in SYMTAB2
            for (int j = 1; j < symbol_count2; j++) {
                Elf32_Sym *symbol2 = &symbols2[j];
                const char *name2 = strtab2 + symbol2->st_name;
                if (strcmp(name1, name2) == 0 && symbol2->st_shndx != SHN_UNDEF) {
                    printf("Symbol %s multiply defined\n", name1);
                    error_found = 1;
                    break;
                }
            }
        }
    }

    if (!error_found) {
        printf("No merge errors found.\n");
    }
}

void merge_elf_files() {
    // Ensure exactly two ELF files are opened and mapped
    if (fd[0] == -1 || fd[1] == -1) {
        printf("Error: Need exactly two ELF files opened and mapped.\n");
        return;
    }

    Elf32_Ehdr *header1 = (Elf32_Ehdr *)map_start[0];
    Elf32_Ehdr *header2 = (Elf32_Ehdr *)map_start[1];

    // Assume header1 will be used as the base for output file
    int fd_out = open("out.ro", O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd_out == -1) {
        perror("Error creating output file");
        return;
    }

    // Copy header1 as the base for output file
    write(fd_out, header1, sizeof(Elf32_Ehdr));

    // Create an initial version of section header table for merged file
    Elf32_Shdr *section_headers1 = (Elf32_Shdr *)(map_start[0] + header1->e_shoff);
    Elf32_Shdr *section_headers2 = (Elf32_Shdr *)(map_start[1] + header2->e_shoff);

    Elf32_Shdr *section_headers_out = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr) * header1->e_shnum);
    memcpy(section_headers_out, section_headers1, sizeof(Elf32_Shdr) * header1->e_shnum);

    // Update section header table offsets and sizes for merged sections
    int offset = sizeof(Elf32_Ehdr) + (header1->e_shnum * sizeof(Elf32_Shdr));
    for (int i = 0; i < header1->e_shnum; i++) {
        if (strcmp(".text", (char *)(map_start[0] + section_headers1[i].sh_name)) == 0) {
            // Concatenate ".text" section from both ELF files
            write(fd_out, map_start[0] + section_headers1[i].sh_offset, section_headers1[i].sh_size);
            write(fd_out, map_start[1] + section_headers2[i].sh_offset, section_headers2[i].sh_size);

            section_headers_out[i].sh_offset = offset;
            section_headers_out[i].sh_size = section_headers1[i].sh_size + section_headers2[i].sh_size;

            offset += section_headers_out[i].sh_size;
        } else {
            // Copy other sections from the first ELF file
            write(fd_out, map_start[0] + section_headers1[i].sh_offset, section_headers1[i].sh_size);
        }
    }

    // Write the updated section header table to output file
    lseek(fd_out, sizeof(Elf32_Ehdr), SEEK_SET);
    write(fd_out, section_headers_out, sizeof(Elf32_Shdr) * header1->e_shnum);

    // Update e_shoff field in ELF header
    header1->e_shoff = sizeof(Elf32_Ehdr);

    lseek(fd_out, 0, SEEK_SET);
    write(fd_out, header1, sizeof(Elf32_Ehdr));

    close(fd_out);
    free(section_headers_out);

    printf("Merge completed. Output file: out.ro\n");
}


void quit() {
    for (int i = 0; i < MAX_FILES; i++) {
        if (fd[i] != -1) {
            munmap(map_start[i], sizeof(map_start[i]));
            close(fd[i]);
            free(file_names[i]);
        }
    }
    exit(0);
}

void print_menu() {
    printf("Choose action:\n");
    for (int i = 0; i < sizeof(menu) / sizeof(menu_option); i++) {
        printf("%d-%s\n", i, menu[i].name);
    }
}

int main() {
    while (1) {
        print_menu();
        int choice;
        scanf("%d", &choice);
        if (choice < 0 || choice >= sizeof(menu) / sizeof(menu_option)) {
            printf("Invalid choice\n");
            continue;
        }
        menu[choice].func();
    }
    return 0;
}
