#include <elf.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


typedef struct {
    int count;
    char debug_mode;
    void* addr;
    unsigned int size;
    char fileName[100];
    int fd;
    void* addr1;
    unsigned int size1;
    int fd1;
    char fileName1[100];
} state;

struct fun_desc {
    char *name;
    void (*func)(state*);
};

char* sh_type(Elf32_Shdr section){
    if(section.sh_type == SHT_NULL) return "NULL";
    if(section.sh_type == SHT_PROGBITS) return "PROGBITS";
    if(section.sh_type == SHT_SYMTAB) return "SYMTAB";
    if(section.sh_type == SHT_STRTAB) return "STRTAB";
    if(section.sh_type == SHT_RELA) return "RELA";
    if(section.sh_type == SHT_HASH) return "HASH";
    if(section.sh_type == SHT_DYNAMIC) return "DYNAMIC";
    if(section.sh_type == SHT_NOTE) return "NOTE";
    if(section.sh_type == SHT_NOBITS) return "NOBITS";
    if(section.sh_type == SHT_REL) return "REL";
    if(section.sh_type == SHT_SHLIB) return "SHLIB";
    if(section.sh_type == SHT_DYNSYM) return "DYNSYM";
    if(section.sh_type == SHT_INIT_ARRAY) return "INIT_ARRAY";
    if(section.sh_type == SHT_FINI_ARRAY) return "FINI_ARRAY";
    if(section.sh_type == SHT_PREINIT_ARRAY) return "PREINIT_ARRAY";
    if(section.sh_type == SHT_GROUP) return "GROUP";
    if(section.sh_type == SHT_SYMTAB_SHNDX) return "SYMTAB_SHNDX";
    if(section.sh_type == SHT_NUM) return "NUM";
    if(section.sh_type == SHT_LOOS) return "LOOS";
    if(section.sh_type == SHT_GNU_ATTRIBUTES) return "GNU_ATTRIBUTES";
    if(section.sh_type == SHT_GNU_HASH) return "GNU_HASH";
    if(section.sh_type == SHT_GNU_LIBLIST) return "GNU_LIBLIST";
    if(section.sh_type == SHT_CHECKSUM) return "CHECKSUM";
    if(section.sh_type == SHT_LOSUNW) return "LOSUNW";
    if(section.sh_type == SHT_SUNW_move) return "SUNW_move";
    if(section.sh_type == SHT_SUNW_COMDAT) return "SUNW_COMDAT";
    if(section.sh_type == SHT_SUNW_syminfo) return "SUNW_syminfo";
    if(section.sh_type == SHT_GNU_verdef) return "GNU_verdef";
    if(section.sh_type == SHT_GNU_verneed) return "GNU_verneed";
    if(section.sh_type == SHT_GNU_versym) return "GNU_versym";
    if(section.sh_type == SHT_HISUNW) return "HISUNW";
    if(section.sh_type == SHT_HIOS) return "HIOS";
    if(section.sh_type == SHT_LOPROC) return "LOPROC";
    if(section.sh_type == SHT_HIPROC) return "HIPROC";
    if(section.sh_type == SHT_LOUSER) return "LOUSER";
    if(section.sh_type == SHT_HIUSER) return "HIUSER";
    return "";
}
    

void Toggle_Debug_Mode(state* s){
    if (s->debug_mode=='t')
    {
        s->debug_mode = 'f';
        printf("Debug flag now off\n");
    }
    else
    {
        s->debug_mode = 't';
        printf("Debug flag now on\n");
    }
}

void Examine_ELF_File(state* s){
    printf("Enter file name:\n");
    char fileName[100];
    fgets(fileName, 100, stdin);
    fileName[strlen(fileName)-1] = '\0';
    int fd = open(fileName, O_RDONLY);
    struct stat  sb;
    if (fd == -1){
        perror("open");
        return;
    }
    if (fstat(fd, &sb) == -1){
        perror("fstat");
        return;
    }
    void* addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED){
        perror("mmap");
        return;
    }
    Elf32_Ehdr* header = (Elf32_Ehdr*) addr;
    if(header->e_ident[0] == ELFMAG0 && header->e_ident[1] == ELFMAG1 && 
        header->e_ident[2] == ELFMAG2 && header->e_ident[3] == ELFMAG3){
        if(s->count == 0){
            s->addr = addr;
            s->size = sb.st_size;
            s->fd = fd;
            s->count++;
            strcpy(s->fileName, fileName);
        } else if(s->count == 1) {
            s->addr1 = addr;
            s->size1 = sb.st_size;
            s->fd1 = fd;
            s->count++;
            strcpy(s->fileName1, fileName);
        } else {
            printf("You have opened the maximum amount of files!\n");
        }
        printf("Magic: %X %X %X %X\n", header->e_ident[0], header->e_ident[1], header->e_ident[2], header->e_ident[3]);
        printf("Data: %s\n", (header->e_ident[EI_DATA] == ELFDATA2LSB) ? "2's complement, little endian" : "2's complement, big endian");
        printf("Entry point: 0x%08X\n", header->e_entry);
        printf("Section Header Table Offset: %d\n", header->e_shoff);
        printf("Section Header Count: %d\n", header->e_shnum);
        printf("Section Header Size: %d\n", header->e_shentsize);
        printf("Program Header Table Offset: %d\n", header->e_phoff);
        printf("Program Header Count: %d\n", header->e_phnum);
        printf("Program Header Size: %d\n", header->e_phentsize);
    } else {
        printf("Not an elf file!\n");
    }
}
void Print_Section_Names_Helper(void* addr){
    Elf32_Ehdr* header = (Elf32_Ehdr*) addr;
    Elf32_Shdr* sections = (Elf32_Shdr*) (addr + header->e_shoff);
    char* sectionsNames = (char*)(addr + sections[header->e_shstrndx].sh_offset);
    for(int i = 0; i < header->e_shnum; i++){
        //[index] section_name section_address section_offset section_size  section_type
        printf("[%02d] %-20s %08x %06x %05x %s\n", i, sectionsNames+sections[i].sh_name, sections[i].sh_addr, 
        sections[i].sh_offset, sections[i].sh_size, sh_type(sections[i]));
    }
}
void Print_Section_Names(state* s){
    if(s->count == 0){
        printf("No open files\n");
    } 
    void* addrs[] = {s->addr, s->addr1};
    char* fileNames[] = {s->fileName, s->fileName1};

    for(int i = 0; i < s->count; i++){
        printf("File: %s\n", fileNames[i]);
        Print_Section_Names_Helper(addrs[i]);
        if (i < s->count - 1) {
            printf("\n"); 
        }
    }
}
void Print_Symbols_helper(void* addr){
    Elf32_Ehdr* header = (Elf32_Ehdr*) addr;
    Elf32_Shdr* sections = (Elf32_Shdr*) (addr + header->e_shoff);
    char* sectionsNames = (char*)(addr + sections[header->e_shstrndx].sh_offset);
    for(int i = 0; i < header->e_shnum; i++){
        if(sections[i].sh_type == SHT_DYNSYM || sections[i].sh_type == SHT_SYMTAB){
            int symbol_size = sections[i].sh_size / sections[i].sh_entsize;
            //sh_link includes the linked section, in this case the linked section is the string table of that symbol table
            char* symbolsNames = (char*)(addr + sections[sections[i].sh_link].sh_offset);
            Elf32_Sym* symbols = (Elf32_Sym*)(addr + sections[i].sh_offset);
            for(int j = 0; j < symbol_size; j++){
                //[index] value section_index section_name symbol_name 
                if(symbols[j].st_shndx == SHN_ABS){
                    printf("[%02d] %08X ABS %-20s %-20s\n", j, symbols[j].st_value, "", symbolsNames + symbols[j].st_name);
                } else if(symbols[j].st_shndx == SHN_UNDEF){
                    printf("[%02d] %08X UND %-20s %-20s\n", j, symbols[j].st_value, "", symbolsNames + symbols[j].st_name);
                } else {
                    printf("[%02d] %08X %03d %-20s %-20s\n", j, symbols[j].st_value, symbols[j].st_shndx, sectionsNames + sections[symbols[j].st_shndx].sh_name, symbolsNames + symbols[j].st_name);
                }
            }
        }
    }
}
void Print_Symbols(state* s){
    if(s->count == 0){
        printf("No open files\n");
    } else if(s->count == 1){
        printf("File: %s\n", s->fileName);
        Print_Symbols_helper(s->addr);
    } else {
        printf("File: %s\n", s->fileName);
        Print_Symbols_helper(s->addr);
        printf("\nFile: %s\n", s->fileName1);
        Print_Symbols_helper(s->addr1);
    }
}

void Check_Files_for_Merge(state* s){
    if(s->count != 2){
        printf("You don't have two opened ELF files!\n");
        return;
    }
    int counter = 0;
    int symbol_size1;
    char* symbolsNames1;
    Elf32_Sym* symbols1;
    Elf32_Ehdr* header1 = (Elf32_Ehdr*) s->addr;
    Elf32_Shdr* sections1 = (Elf32_Shdr*) (s->addr + header1->e_shoff);
    for(int i = 0; i < header1->e_shnum; i++){
        if(sections1[i].sh_type == SHT_DYNSYM || sections1[i].sh_type == SHT_SYMTAB){
            counter++;
            symbol_size1 = sections1[i].sh_size / sections1[i].sh_entsize;
            symbolsNames1 = (char*)(s->addr + sections1[sections1[i].sh_link].sh_offset);
            symbols1 = (Elf32_Sym*)(s->addr + sections1[i].sh_offset);
        }
    }
    if(counter != 1){
        printf("Feature not supported!\n");
        return;
    }

    counter = 0;
    int symbol_size2;
    char* symbolsNames2;
    Elf32_Sym* symbols2;
    Elf32_Ehdr* header2 = (Elf32_Ehdr*) s->addr1;
    Elf32_Shdr* sections2 = (Elf32_Shdr*) (s->addr1 + header2->e_shoff);
    for(int i = 0; i < header2->e_shnum; i++){
        if(sections2[i].sh_type == SHT_DYNSYM || sections2[i].sh_type == SHT_SYMTAB){
            counter++;
            symbol_size2 = sections2[i].sh_size / sections2[i].sh_entsize;
            symbolsNames2 = (char*)(s->addr1 + sections2[sections2[i].sh_link].sh_offset);
            symbols2 = (Elf32_Sym*)(s->addr1 + sections2[i].sh_offset);
        }
    }
    if(counter != 1){
        printf("Feature not supported!\n");
        return;
    }

    for(int i = 1; i < symbol_size1; i++){
        char* name1 = symbolsNames1 + symbols1[i].st_name;
        int found = 0;
        if(strcmp(name1, "") != 0){
            for(int j = 1; j < symbol_size2; j++){
                char* name2 = symbolsNames2 + symbols2[j].st_name;
                if(strcmp(name1, name2) == 0){
                    found = 1;
                    if(symbols1[i].st_shndx == SHN_UNDEF && symbols2[j].st_shndx == SHN_UNDEF){
                        printf("symbol %s is undefined\n", name1);
                    } else if(symbols1[i].st_shndx != SHN_UNDEF && symbols2[j].st_shndx != SHN_UNDEF){
                        printf("symbol %s is multiply defined\n", name1);
                    }
                }
            }
            if(found == 0 && symbols1[i].st_shndx == SHN_UNDEF){
                printf("symbol1 %s is undefined\n", name1);
            }
        }
    }

    for(int i = 1; i < symbol_size2; i++){
        char* name2 = symbolsNames2 + symbols2[i].st_name;
        int found = 0;
        if(strcmp(name2, "") != 0){
            for(int j = 1; j < symbol_size1; j++){
                char* name1 = symbolsNames1 + symbols1[j].st_name;
                if(strcmp(name2, name1) == 0){
                    found = 1;
                    if(symbols2[i].st_shndx == SHN_UNDEF && symbols1[j].st_shndx == SHN_UNDEF){
                        printf("symbol %s is undefined\n", name2);
                    } else if(symbols2[i].st_shndx != SHN_UNDEF && symbols1[j].st_shndx != SHN_UNDEF){
                        printf("symbol %s is multiply defined\n", name2);
                    }
                }
            }
            if(found == 0 && symbols2[i].st_shndx == SHN_UNDEF){
                printf("symbol %s is undefined\n", name2);
            }
        }
    }
}

void Merge_ELF_Files(state* s){
    printf("Not implemented yet\n");
}

void Quit(state* s){
    if(s->count == 1){
        munmap(s->addr, s->size);
        close(s->fd);
    } else if(s->count == 2){
        munmap(s->addr, s->size);
        close(s->fd);
        munmap(s->addr1, s->size1);
        close(s->fd1);
    }
    free(s);
    exit(0);
}


struct fun_desc menu[] = {
    {"Toggle Debug Mode", Toggle_Debug_Mode}, {"Examine ELF File", Examine_ELF_File},
    {"Print Section Names", Print_Section_Names}, {"Print Symbols", Print_Symbols},
    {"Check Files for Merge", Check_Files_for_Merge}, {"Merge ELF Files", Merge_ELF_Files},
    {"Quit", Quit}, {NULL, NULL} 
};

int main(){
    state* s = malloc(sizeof(state));
    while (1) {
        printf("Select operation from the following menu:\n");
        int i=0;
        while(menu[i].name != NULL && menu[i].func != NULL){
            printf("%d). %s\n", i, menu[i].name);
            i++;
        }
        printf("Option : ");

        char buffer[100];
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            if (feof(stdin)) {
                exit(0);
            } else {
                exit(1);
            }
        }
        int option;
        sscanf(buffer, "%d", &option);
        if(option >= 0 && option < i){
            menu[option].func(s);
        }
        else
        {
            printf("\nNot within bounds\n\n");
        }

    }
    return 0;
}