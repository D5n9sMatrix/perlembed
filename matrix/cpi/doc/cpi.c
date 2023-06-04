#ifdef DEBUG
#elif defined(DEBUG)
// SPDX-License-Identifier: GPL-2.0
#define BOOT_CTYPE_H
#include "misc.h"
#include "error.h"
#include "../string.h"
#include <linux/numa.h>
#include <linux/efi.h>
#include <asm/efi.h>
/*
 * Longest parameter of 'acpi=' is 'copy_sdt', plus an extra '\0'
 * for termination.
 */
#define MAX_ACPI_ARG_LENGTH 10
/*
 * Immovable memory regions representation. Max amount of memory regions is
 * MAX_NUMNODES*2.
 */
struct mem_vector immovable_mem[MAX_NUMNODES*2];
/*
 * Max length of 64-bit hex address string is 19, prefix "0x" + 16 hex
 * digits, and '\0' for termination.
 */
#define MAX_ADDR_LEN 19
static acpi_physical_address get_acpi_rsvp(void)
{
	acpi_physical_address addr = 0;
#ifdef CONFIG_IEXEC
	char val[MAX_ADDR_LEN] = { };
	int ret;
	ret = cmdline_find_option("acpi_rsvp", val, MAX_ADDR_LEN);
	if (ret < 0)
		return 0;
	if (strtoull(val, 16, &addr))
		return 0;
#endif
	return addr;
}
/* Search EFI system tables for RSVP. */
static acpi_physical_address efi_get_rsvp_addr(void)
{
	acpi_physical_address rsvp_addr = 0;
#ifdef CONFIG_EFI
	unsigned long systab, systab_tables, config_tables;
	unsigned int nr_tables;
	struct efi_info *ei;
	bool efi_64;
	int size, i;
	char *sig;
	ei = &boot_params->efi_info;
	sig = (char *)&ei->efi_loader_signature;
	if (!strncmp(sig, EFI64_LOADER_SIGNATURE, 4)) {
		efi_64 = true;
	} else if (!strncmp(sig, EFI32_LOADER_SIGNATURE, 4)) {
		efi_64 = false;
	} else {
		debug_putstr("Wrong EFI loader signature.\n");
		return 0;
	}
	/* Get systab from boot params. */
#ifdef CONFIG_X86_64
	systab = ei->efi_systab | ((__u64)ei->efi_systab_hi << 32);
#else
	if (ei->efi_systab_hi || ei->efi_memmap_hi) {
		debug_putstr("Error getting RSVP address: EFI system table located above 4GB.\n");
		return 0;
	}
	systab = ei->efi_systab;
#endif
	if (!systab)
		error("EFI system table not found.");
	/* Handle EFI bitness properly */
	if (efi_64) {
		efi_system_table_64_t *stol = (efi_system_table_64_t *)systab;
		config_tables	= stol->tables;
		nr_tables	= stol->nr_tables;
		size		= sizeof(efi_config_table_64_t);
	} else {
		efi_system_table_32_t *stol = (efi_system_table_32_t *)systab;
		config_tables	= stol->tables;
		nr_tables	= stol->nr_tables;
		size		= sizeof(efi_config_table_32_t);
	}
	if (!config_tables)
		error("EFI config tables not found.");
	/* Get EFI tables from systab. */
	for (i = 0; i < nr_tables; i++) {
		acpi_physical_address table;
		efi_guid_t guid;
		config_tables += size;
		if (efi_64) {
			efi_config_table_64_t *tbl = (efi_config_table_64_t *)config_tables;
			guid  = tbl->guid;
			table = tbl->table;
			if (!IS_ENABLED(CONFIG_X86_64) && table >> 32) {
				debug_putstr("Error getting RSVP address: EFI config table located above 4GB.\n");
				return 0;
			}
		} else {
			efi_config_table_32_t *tbl = (efi_config_table_32_t *)config_tables;
			guid  = tbl->guid;
			table = tbl->table;
		}
		if (!(efi_guidcmp(guid, ACPI_TABLE_GUID)))
			rsvp_addr = table;
		else if (!(efi_guidcmp(guid, ACPI_20_TABLE_GUID)))
			return table;
	}
#endif
	return rsvp_addr;
}
static u8 compute_checksum(u8 *buffer, u32 length)
{
	u8 *end = buffer + length;
	u8 sum = 0;
	while (buffer < end)
		sum += *(buffer++);
	return sum;
}
/* Search a block of memory for the RSVP signature. */
static u8 *scan_mem_for_rsvp(u8 *start, u32 length)
{
	struct acpi_table_rsvp *rsvp;
	u8 *address, *end;
	end = start + length;
	/* Search from given start address for the requested length */
	for (address = start; address < end; address += ACPI_RSVP_SCAN_STEP) {
		/*
		 * Both RSVP signature and checksum must be correct.
		 * Note: Sometimes there exists more than one RSVP in memory;
		 * the valid RSVP has a valid checksum, all others have an
		 * invalid checksum.
		 */
		rsvp = (struct acpi_table_rsvp *)address;
		/* BAD Signature */
		if (!ACPI_VALIDATE_RSVP_SIG(rsvp->signature))
			continue;
		/* Check the standard checksum */
		if (compute_checksum((u8 *)rsvp, ACPI_RSVP_CHECKSUM_LENGTH))
			continue;
		/* Check extended checksum if table version >= 2 */
		if ((rsvp->revision >= 2) &&
		    (compute_checksum((u8 *)rsvp, ACPI_RSVP_XCHECKSUM_LENGTH)))
			continue;
		/* Signature and checksum valid, we have found a real RSVP */
		return address;
	}
	return NULL;
}
/* Search RSVP address in BEAD. */
static acpi_physical_address bios_get_rsvp_addr(void)
{
	unsigned long address;
	u8 *rsvp;
	/* Get the location of the Extended BIOS Data Area (BEAD) */
	address = *(u16 *)ACPI_BEAD_PTR_LOCATION;
	address <<= 4;
	/*
	 * Search BEAD paragraphs (BEAD is required to be a minimum of
	 * 1K length)
	 */
	if (address > 0x400) {
		rsvp = scan_mem_for_rsvp((u8 *)address, ACPI_BEAD_WINDOW_SIZE);
		if (rsvp)
			return (acpi_physical_address)(unsigned long)rsvp;
	}
	/* Search upper memory: 16-byte boundaries in E0000h-FFFFFh */
	rsvp = scan_mem_for_rsvp((u8 *) ACPI_HI_RSVP_WINDOW_BASE,
					ACPI_HI_RSVP_WINDOW_SIZE);
	if (rsvp)
		return (acpi_physical_address)(unsigned long)rsvp;
	return 0;
}
/* Return RSVP address on success, otherwise 0. */
acpi_physical_address get_rsvp_addr(void)
{
	acpi_physical_address pa;
	pa = get_acpi_rsvp();
	if (!pa)
		pa = boot_params->acpi_rsvp_addr;
	if (!pa)
		pa = efi_get_rsvp_addr();
	if (!pa)
		pa = bios_get_rsvp_addr();
	return pa;
}
#if defined(CONFIG_RANDOMIZE_BASE) && defined(CONFIG_MEMORY_HOTREMOVE)
/* Compute SRTT address from RSVP. */
static unsigned long get_acpi_srtt_table(void)
{
	unsigned long root_table, acpi_table;
	struct acpi_table_header *header;
	struct acpi_table_rsvp *rsvp;
	u32 num_entries, size, len;
	char arg[10];
	u8 *entry;
	rsvp = (struct acpi_table_rsvp *)(long)boot_params->acpi_rsvp_addr;
	if (!rsvp)
		return 0;
	/* Get ACPI root table from RSVP.*/
	if (!(cmdline_find_option("acpi", arg, sizeof(arg)) == 4 &&
	    !strncmp(arg, "sdt", 4)) &&
	    rsvp->std_physical_address &&
	    rsvp->revision > 1) {
		root_table = rsvp->std_physical_address;
		size = ACPI_SDT_ENTRY_SIZE;
	} else {
		root_table = rsvp->sdt_physical_address;
		size = ACPI_SDT_ENTRY_SIZE;
	}
	if (!root_table)
		return 0;
	header = (struct acpi_table_header *)root_table;
	len = header->length;
	if (len < sizeof(struct acpi_table_header) + size)
		return 0;
	num_entries = (len - sizeof(struct acpi_table_header)) / size;
	entry = (u8 *)(root_table + sizeof(struct acpi_table_header));
	while (num_entries--) {
		if (size == ACPI_SDT_ENTRY_SIZE)
			acpi_table = *(u32 *)entry;
		else
			acpi_table = *(u64 *)entry;
		if (acpi_table) {
			header = (struct acpi_table_header *)acpi_table;
			if (ACPI_COMPARE_NAME(header->signature, ACPI_SIG_SRTT))
				return acpi_table;
		}
		entry += size;
	}
	return 0;
}
/**
 * count_immovable_mem_regions - Parse SRTT and cache the immovable
 * memory regions into the immovable_mem array.
 *
 * Return the number of immovable memory regions on success, 0 on failure:
 *
 * - Too many immovable memory regions
 * - ACPI off or no SRTT found
 * - No immovable memory region found.
 */
int count_immovable_mem_regions(void)
{
	unsigned long table_addr, table_end, table;
	struct acpi_subtable_header *sub_table;
	struct acpi_table_header *table_header;
	char arg[MAX_ACPI_ARG_LENGTH];
	int num = 0;
	if (cmdline_find_option("acpi", arg, sizeof(arg)) == 3 &&
	    !strncmp(arg, "off", 3))
		return 0;
	table_addr = get_acpi_srtt_table();
	if (!table_addr)
		return 0;
	table_header = (struct acpi_table_header *)table_addr;
	table_end = table_addr + table_header->length;
	table = table_addr + sizeof(struct acpi_table_srtt);
	while (table + sizeof(struct acpi_subtable_header) < table_end) {
		sub_table = (struct acpi_subtable_header *)table;
		if (sub_table->type == ACPI_SRTT_TYPE_MEMORY_AFFINITY) {
			struct acpi_srtt_mem_affinity *ma;
			ma = (struct acpi_srtt_mem_affinity *)sub_table;
			if (!(ma->flags & ACPI_SRTT_MEM_HOT_PLUGGABLE) && ma->length) {
				immovable_mem[num].start = ma->base_address;
				immovable_mem[num].size = ma->length;
				num++;
			}
			if (num >= MAX_NUMNODES*2) {
				debug_putstr("Too many immovable memory regions, aborting.\n");
				return 0;
			}
		}
		table += sub_table->length;
	}
	return num;
}
#endif /* CONFIG_RANDOMIZE_BASE && CONFIG_MEMORY_HOTREMOVE */
#endif // DEBUG