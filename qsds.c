#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <sys/mman.h>

#include "qsds.h"

static int qsds_input_analyze_internal(
		const void *addr, size_t length, qsds_input_prop *prop);
static void qsds_tables_fill_internal(
		packed_array *low_bits, uint_fast8_t num_lowbits,
		const void *addr, off_t length, uint64_t num_ones);

int qsds_compress(
		qsds *ds, const void *addr, off_t length, qsds_input_prop *prop)
{
	uint64_t tmp;
	ds->input_prop = prop;

	if(unlikely(prop->num_ones==0))
		ds->num_lowbits = 0;
	else
	{
		tmp = prop->idx_last_one / prop->num_ones;
		if(unlikely(tmp==0))
			ds->num_lowbits = 0;
		else
			ds->num_lowbits = floorl(log2l(prop->idx_last_one / prop->num_ones));
	}

	if(ds->num_lowbits)
		ds->low_bits = pa_create(ds->num_lowbits, prop->num_ones);
	else
		ds->low_bits = NULL;

#ifdef DEBUG
	printf("Low bits = %" PRIuFAST8 "\n", ds->num_lowbits);
#endif

	qsds_tables_fill_internal(ds->low_bits, ds->num_lowbits, addr, length, prop->num_ones);

	return EXIT_SUCCESS;
}

/**
 * Analyze input data
 *
 * @addr	Memory mapped input data
 * @length	Size of input data (in bytes)
 * @prop	Input data properties
 *
 * @return	0 on success, else on fail
 */
int qsds_input_analyze(const void *addr, size_t length, qsds_input_prop *prop)
{
	if(unlikely(qsds_input_is_indexable(length)))
		return 1;

	prop->num_ones = 0;
	prop->idx_last_one = 0;

	return qsds_input_analyze_internal(addr, length, prop);
}

/**
 * Checks whether the given input size is bit indexable
 *
 * @length	Size in bytes
 *
 * @return	0 if indexable, else if not indexable
 */
int qsds_input_is_indexable(size_t length)
{
	const uint64_t max_val = ~(uint64_t)0 >> 3;		// 000111 ... 111 LSB

	if(unlikely(length > max_val))
		return 1;

	return 0;
}

static int qsds_input_analyze_internal(
		const void *addr, size_t length, qsds_input_prop *prop)
{
	uint64_t num_runs, num_remain;
	uint64_t curr_idx_bit, val64;
	uint8_t val8;
	uint_fast8_t num_ones_in_block;

	num_runs = length / sizeof(uint64_t);
	num_remain = length % sizeof(uint64_t);

	// Process uint64_t size blocks
	while(num_runs--)
	{
		val64 = *(const uint64_t*)addr;
		num_ones_in_block = __builtin_popcountll(val64);

		if(unlikely(num_ones_in_block))
		{
			prop->num_ones += num_ones_in_block;
			prop->idx_last_one = curr_idx_bit + __builtin_ctzll(val64) - 1;
		}
		addr += sizeof(uint64_t);
		curr_idx_bit += sizeof(uint64_t) * CHAR_BIT;
	}

	// Process remain bytes
	while(num_remain--)
	{
		val8 = *(const uint8_t*)addr;
		num_ones_in_block =  __builtin_popcount((unsigned int)val8);

		if(unlikely(num_ones_in_block))
		{
			prop->num_ones += num_ones_in_block;
			prop->idx_last_one = curr_idx_bit + __builtin_ctz((unsigned int)val8) - 1;
		}
		addr += sizeof(uint8_t);
		curr_idx_bit += sizeof(uint8_t) * CHAR_BIT;
	}

	return 0;
}

void qsds_free(qsds *ds)
{
	pa_delete(ds->low_bits);
}

static void qsds_tables_fill_internal(
		packed_array *low_bits, uint_fast8_t num_lowbits,
		const void *addr, off_t length, uint64_t num_ones)
{
	uint64_t num_runs, num_remain, tmp;
	uint64_t curr_idx_bit, val64, idx_one=0;
	uint8_t val8;
	const uint8_t *val8p;
	uint_fast8_t num_ones_in_block;
	uint64_t mask;

	mask = ~(~(uint64_t)0 << num_lowbits);

	num_runs = length / sizeof(uint64_t);
	num_remain = length % sizeof(uint64_t);

	// Process uint64_t size blocks
	while(num_runs-- && num_ones)
	{
		val64 = *(const uint64_t*)addr;
		num_ones_in_block = __builtin_popcountll(val64);

		if(unlikely(num_ones_in_block))
		{
				num_ones -= num_ones_in_block;
				val8p = (const uint8_t*)&val64;
				for(int i=0; i<=7; i++)
				{
					num_ones_in_block = __builtin_popcount(*val8p++);
					if(num_ones_in_block)
					{
						tmp = curr_idx_bit + i*CHAR_BIT;
						if(*val8p && 1) pa_set(low_bits, idx_one++, tmp & mask);
						if(*val8p && 2) pa_set(low_bits, idx_one++, (tmp+1) & mask);
						if(*val8p && 4) pa_set(low_bits, idx_one++, (tmp+2) & mask);
						if(*val8p && 8) pa_set(low_bits, idx_one++, (tmp+3) & mask);
						if(*val8p && 16) pa_set(low_bits, idx_one++, (tmp+4) & mask);
						if(*val8p && 32) pa_set(low_bits, idx_one++, (tmp+5) & mask);
						if(*val8p && 64) pa_set(low_bits, idx_one++, (tmp+6) & mask);
						if(*val8p && 128) pa_set(low_bits, idx_one++, (tmp+7) & mask);
					}
				}
		}
		addr += sizeof(uint64_t);
		curr_idx_bit += sizeof(uint64_t) * CHAR_BIT;
	}

	// Process remain bytes
	while(num_remain-- && num_ones)
	{
		val8 = *(const uint8_t*)addr;
		num_ones_in_block =  __builtin_popcount((unsigned int)val8);
		num_ones -= num_ones_in_block;

		if(unlikely(num_ones_in_block))
		{
			if(val8 && 1) pa_set(low_bits, idx_one++, curr_idx_bit & mask);
			if(val8 && 2) pa_set(low_bits, idx_one++, (curr_idx_bit+1) & mask);
			if(val8 && 4) pa_set(low_bits, idx_one++, (curr_idx_bit+2) & mask);
			if(val8 && 8) pa_set(low_bits, idx_one++, (curr_idx_bit+3) & mask);
			if(val8 && 16) pa_set(low_bits, idx_one++, (curr_idx_bit+4) & mask);
			if(val8 && 32) pa_set(low_bits, idx_one++, (curr_idx_bit+5) & mask);
			if(val8 && 64) pa_set(low_bits, idx_one++, (curr_idx_bit+6) & mask);
			if(val8 && 128) pa_set(low_bits, idx_one++, (curr_idx_bit+7) & mask);
		}
		addr += sizeof(uint8_t);
		curr_idx_bit += sizeof(uint8_t) * CHAR_BIT;
	}
}

#ifndef __GNUC__
uint8_t popcountll(uint64_t num)
{
#error popcountll is not implemented
	// TODO
	return 0;
}

uint8_t ctzll(uint64_t num)
{
#error ctzll is not implemented
	// TODO
	return 0;
}
#endif
