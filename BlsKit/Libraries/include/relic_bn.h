/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @defgroup bn Multiple precision integer arithmetic
 */

/**
 * @file
 *
 * Interface of the module for multiple precision integer arithmetic.
 *
 * @ingroup bn
 */

#ifndef RLC_relic_bn_H
#define RLC_relic_bn_H

#include "relic_conf.h"
#include "relic_util.h"
#include "relic_types.h"
#include "relic_label.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/**
 * Precision in bits of a multiple precision integer.
 *
 * If the library is built with support for dynamic allocation, this constant
 * represents the size in bits of the memory block allocated each time a
 * multiple precision integer must grow. Otherwise, it represents the fixed
 * fixed precision.
 */
#define RLC_relic_bn_BITS 	((int)relic_bn_PRECI)

/**
 * Size in digits of a block sufficient to store the required precision.
 */
#define RLC_relic_bn_DIGS		((int)RLC_CEIL(relic_bn_PRECI, RLC_DIG))

/**
 * Size in digits of a block sufficient to store a multiple precision integer.
 */
#if relic_bn_MAGNI == DOUBLE
#define RLC_RELIC_BN_SIZE		((int)(2 * RLC_relic_bn_DIGS + 2))
#elif relic_bn_MAGNI == CARRY
#define RLC_RELIC_BN_SIZE		((int)(RLC_relic_bn_DIGS + 1))
#elif relic_bn_MAGNI == SINGLE
#define RLC_RELIC_BN_SIZE		((int)RLC_relic_bn_DIGS)
#endif

/**
 * Positive sign of a multiple precision integer.
 */
#define RLC_POS		0

/**
 * Negative sign of a multiple precision integer.
 */
#define RLC_NEG		1

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Represents a multiple precision integer.
 *
 * The field dp points to a vector of digits. These digits are organized
 * in little-endian format, that is, the least significant digits are
 * stored in the first positions of the vector.
 */
typedef struct {
	/** The number of digits allocated to this multiple precision integer. */
	int alloc;
	/** The number of digits actually used. */
	int used;
	/** The sign of this multiple precision integer. */
	int sign;
#if ALLOC == DYNAMIC
	/** The sequence of contiguous digits that forms this integer. */
	dig_t *dp;
#elif ALLOC == STACK || ALLOC == AUTO
	/** The sequence of contiguous digits that forms this integer. */
	rlc_align dig_t dp[RLC_RELIC_BN_SIZE];
#endif
} relic_bn_st;

/**
 * Pointer to a multiple precision integer structure.
 */
#if ALLOC == AUTO
typedef relic_bn_st relic_bn_t[1];
#else
typedef relic_bn_st *relic_bn_t;
#endif

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Initializes a multiple precision integer with a null value.
 *
 * @param[out] A			- the multiple precision integer to initialize.
 */
#if ALLOC == AUTO
#define relic_bn_null(A)				/* empty */
#else
#define relic_bn_null(A)			A = NULL;
#endif

/**
 * Calls a function to allocate and initialize a multiple precision integer.
 *
 * @param[in,out] A			- the multiple precision integer to initialize.
 * @throw ERR_NO_MEMORY		- if there is no available memory.
 */
#if ALLOC == DYNAMIC
#define relic_bn_new(A)															\
	A = (relic_bn_t)calloc(1, sizeof(relic_bn_st));										\
	if ((A) == NULL) {														\
		THROW(ERR_NO_MEMORY);												\
	}																		\
	relic_bn_init(A, RLC_RELIC_BN_SIZE);												\

#elif ALLOC == AUTO
#define relic_bn_new(A)															\
	relic_bn_init(A, RLC_RELIC_BN_SIZE);												\

#elif ALLOC == STACK
#define relic_bn_new(A)															\
	A = (relic_bn_t)alloca(sizeof(relic_bn_st));										\
	relic_bn_init(A, RLC_RELIC_BN_SIZE);												\

#endif

/**
 * Calls a function to allocate and initialize a multiple precision integer
 * with the required precision in digits.
 *
 * @param[in,out] A			- the multiple precision integer to initialize.
 * @param[in] D				- the precision in digits.
 * @throw ERR_NO_MEMORY		- if there is no available memory.
 * @throw ERR_PRECISION		- if the required precision cannot be represented
 * 							by the library.
 */
#if ALLOC == DYNAMIC
#define relic_bn_new_size(A, D)													\
	A = (relic_bn_t)calloc(1, sizeof(relic_bn_st));										\
	if (A == NULL) {														\
		THROW(ERR_NO_MEMORY);												\
	}																		\
	relic_bn_init(A, D);															\

#elif ALLOC == AUTO
#define relic_bn_new_size(A, D)													\
	relic_bn_init(A, D);															\

#elif ALLOC == STACK
#define relic_bn_new_size(A, D)													\
	A = (relic_bn_t)alloca(sizeof(relic_bn_st));										\
	relic_bn_init(A, D);															\

#endif

/**
 * Calls a function to clean and free a multiple precision integer.
 *
 * @param[in,out] A			- the multiple precision integer to free.
 */
#if ALLOC == DYNAMIC
#define relic_bn_free(A)															\
	if (A != NULL) {														\
		relic_bn_clean(A);														\
		free(A);															\
		A = NULL;															\
	}

#elif ALLOC == AUTO
#define relic_bn_free(A)			/* empty */										\

#elif ALLOC == STACK
#define relic_bn_free(A)															\
	A = NULL;																\

#endif

/**
 * Multiples two multiple precision integers. Computes c = a * b.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the first multiple precision integer to multiply.
 * @param[in] B				- the second multiple precision integer to multiply.
 */
#if relic_bn_KARAT > 0
#define relic_bn_mul(C, A, B)		relic_bn_mul_karat(C, A, B)
#elif relic_bn_MUL == BASIC
#define relic_bn_mul(C, A, B)		relic_bn_mul_basic(C, A, B)
#elif relic_bn_MUL == COMBA
#define relic_bn_mul(C, A, B)		relic_bn_mul_comba(C, A, B)
#endif

/**
 * Computes the square of a multiple precision integer. Computes c = a * a.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the multiple precision integer to square.
 */
#if relic_bn_KARAT > 0
#define relic_bn_sqr(C, A)		relic_bn_sqr_karat(C, A)
#elif relic_bn_SQR == BASIC
#define relic_bn_sqr(C, A)		relic_bn_sqr_basic(C, A)
#elif relic_bn_SQR == COMBA
#define relic_bn_sqr(C, A)		relic_bn_sqr_comba(C, A)
#elif relic_bn_SQR == MULTP
#define relic_bn_sqr(C, A)		relic_bn_mul(C, A, A)
#endif

/**
 * Computes the auxiliar value derived from the modulus to be used during
 * modular reduction.
 *
 * @param[out] U			- the result.
 * @param[in] M				- the modulus.
 */
#if relic_bn_MOD == BASIC
#define relic_bn_mod_pre(U, M)	(void)(U), (void)(M)
#elif relic_bn_MOD == BARRT
#define relic_bn_mod_pre(U, M)	relic_bn_mod_pre_barrt(U, M)
#elif relic_bn_MOD == MONTY
#define relic_bn_mod_pre(U, M)	relic_bn_mod_pre_monty(U, M)
#elif relic_bn_MOD == PMERS
#define relic_bn_mod_pre(U, M)	relic_bn_mod_pre_pmers(U, M)
#endif

/**
 * Reduces a multiple precision integer modulo another integer. If the number
 * of arguments is 3, then simple division is used. If the number of arguments
 * is 4, then a modular reduction algorithm is used and the fourth argument
 * is an auxiliary value derived from the modulus. The variant with 4 arguments
 * should be used when several modular reductions are computed with the same
 * modulus. Computes c = a mod m.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the multiple precision integer to reduce.
 * @param[in] ...			- the modulus and an optional argument.
 */
#define relic_bn_mod(C, A, ...)	RLC_CAT(relic_bn_mod, RLC_OPT(__VA_ARGS__))(C, A, __VA_ARGS__)

/**
 * Reduces a multiple precision integer modulo another integer. This macro
 * should not be called directly. Use relic_bn_mod with 4 arguments instead.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the the multiple precision integer to reduce.
 * @param[in] M				- the modulus.
 * @param[in] U				- the auxiliar value derived from the modulus.
 */
#if relic_bn_MOD == BASIC
#define relic_bn_mod_imp(C, A, M, U)	relic_bn_mod_basic(C, A, M)
#elif relic_bn_MOD == BARRT
#define relic_bn_mod_imp(C, A, M, U)	relic_bn_mod_barrt(C, A, M, U)
#elif relic_bn_MOD == MONTY
#define relic_bn_mod_imp(C, A, M, U)	relic_bn_mod_monty(C, A, M, U)
#elif relic_bn_MOD == PMERS
#define relic_bn_mod_imp(C, A, M, U)	relic_bn_mod_pmers(C, A, M, U)
#endif

/**
 * Reduces a multiple precision integer modulo a positive integer using
 * Montgomery reduction. Computes c = a * u^(-1) (mod m).
 *
 * @param[out] C			- the result.
 * @param[in] A				- the multiple precision integer to reduce.
 * @param[in] M				- the modulus.
 * @param[in] U				- the reciprocal of the modulus.
 */
#if relic_bn_MUL == BASIC
#define relic_bn_mod_monty(C, A, M, U)	relic_bn_mod_monty_basic(C, A, M, U)
#elif relic_bn_MUL == COMBA
#define relic_bn_mod_monty(C, A, M, U)	relic_bn_mod_monty_comba(C, A, M, U)
#endif

/**
 * Exponentiates a multiple precision integer modulo another multiple precision
 * integer. Computes c = a^b mod m. If Montgomery reduction is used, the basis
 * must not be in Montgomery form.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the basis.
 * @param[in] B				- the exponent.
 * @param[in] M				- the modulus.
 */
#if relic_bn_MXP == BASIC
#define relic_bn_mxp(C, A, B, M)	relic_bn_mxp_basic(C, A, B, M)
#elif relic_bn_MXP == SLIDE
#define relic_bn_mxp(C, A, B, M)	relic_bn_mxp_slide(C, A, B, M)
#elif relic_bn_MXP == MONTY
#define relic_bn_mxp(C, A, B, M)	relic_bn_mxp_monty(C, A, B, M)
#endif

/**
 * Computes the greatest common divisor of two multiple precision integers.
 * Computes c = gcd(a, b).
 *
 * @param[out] C			- the result;
 * @param[in] A				- the first multiple precision integer.
 * @param[in] B				- the second multiple precision integer.
 */
#if relic_bn_GCD == BASIC
#define relic_bn_gcd(C, A, B)		relic_bn_gcd_basic(C, A, B)
#elif relic_bn_GCD == LEHME
#define relic_bn_gcd(C, A, B)		relic_bn_gcd_lehme(C, A, B)
#elif relic_bn_GCD == STEIN
#define relic_bn_gcd(C, A, B)		relic_bn_gcd_stein(C, A, B)
#endif

/**
 * Computes the extended greatest common divisor of two multiple precision
 * integers. This function can be used to compute multiplicative inverses.
 * Computes c = gcd(a, b) and c = a * d + b * e.
 *
 * @param[out] C			- the result;
 * @param[out] D			- the cofactor of the first operand, cannot be NULL.
 * @param[out] E			- the cofactor of the second operand, can be NULL.
 * @param[in] A				- the first multiple precision integer.
 * @param[in] B				- the second multiple precision integer.
 */
#if relic_bn_GCD == BASIC
#define relic_bn_gcd_ext(C, D, E, A, B)		relic_bn_gcd_ext_basic(C, D, E, A, B)
#elif relic_bn_GCD == LEHME
#define relic_bn_gcd_ext(C, D, E, A, B)		relic_bn_gcd_ext_lehme(C, D, E, A, B)
#elif relic_bn_GCD == STEIN
#define relic_bn_gcd_ext(C, D, E, A, B)		relic_bn_gcd_ext_stein(C, D, E, A, B)
#endif

/**
 * Generates a probable prime number.
 *
 * @param[out] A			- the result.
 * @param[in] B				- the length of the number in bits.
 */
#if relic_bn_GEN == BASIC
#define relic_bn_gen_prime(A, B)	relic_bn_gen_prime_basic(A, B)
#elif relic_bn_GEN == SAFEP
#define relic_bn_gen_prime(A, B)	relic_bn_gen_prime_safep(A, B)
#elif relic_bn_GEN == STRON
#define relic_bn_gen_prime(A, B)	relic_bn_gen_prime_stron(A, B)
#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Initializes a previously allocated multiple precision integer.
 *
 * @param[out] a			- the multiple precision integer to initialize.
 * @param[in] digits		- the required precision in digits.
 * @throw ERR_NO_MEMORY		- if there is no available memory.
 * @throw ERR_PRECISION		- if the required precision cannot be represented
 * 							by the library.
 */
void relic_bn_init(relic_bn_t a, int digits);

/**
 * Cleans a multiple precision integer.
 *
 * @param[out] a			- the multiple precision integer to free.
 */
void relic_bn_clean(relic_bn_t a);

/**
 * Checks the current precision of a multiple precision integer and optionally
 * expands its precision to a given size in digits.
 *
 * @param[out] a			- the multiple precision integer to expand.
 * @param[in] digits		- the number of digits to expand.
 * @throw ERR_NO_MEMORY		- if there is no available memory.
 * @throw ERR_PRECISION		- if the required precision cannot be represented
 * 							by the library.
 */
void relic_bn_grow(relic_bn_t a, int digits);

/**
 * Adjust the number of valid digits of a multiple precision integer.
 *
 * @param[out] a			- the multiple precision integer to adjust.
 */
void relic_bn_trim(relic_bn_t a);

/**
 * Copies the second argument to the first argument.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to copy.
 */
void relic_bn_copy(relic_bn_t c, const relic_bn_t a);

/**
 * Returns the absolute value of a multiple precision integer.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the argument of the absolute function.
 */
void relic_bn_abs(relic_bn_t c, const relic_bn_t a);

/**
 * Inverts the sign of a multiple precision integer.
 *
 * @param[out] c			- the result.
 * @param[out] a			- the multiple precision integer to negate.
 */
void relic_bn_neg(relic_bn_t c, const relic_bn_t a);

/**
 * Returns the sign of a multiple precision integer.
 *
 * @param[in] a				- the multiple precision integer.
 * @return RLC_POS if the argument is positive and RLC_NEG otherwise.
 */
int relic_bn_sign(const relic_bn_t a);

/**
 * Assigns zero to a multiple precision integer.
 *
 * @param[out] a			- the multiple precision integer to assign.
 */
void relic_bn_zero(relic_bn_t a);

/**
 * Tests if a multiple precision integer is zero or not.
 *
 * @param[in] a				- the multiple precision integer to test.
 * @return 1 if the argument is zero, 0 otherwise.
 */
int relic_bn_is_zero(const relic_bn_t a);

/**
 * Tests if a multiple precision integer is even or odd.
 *
 * @param[in] a				- the multiple precision integer to test.
 * @return 1 if the argument is even, 0 otherwise.
 */
int relic_bn_is_even(const relic_bn_t a);

/**
 * Returns the number of bits of a multiple precision integer.
 *
 * @param[in] a				- the multiple precision integer.
 * @return number of bits.
 */
int relic_bn_bits(const relic_bn_t a);

/**
 * Returns the bit stored in the given position on a multiple precision integer.
 *
 * @param[in] a				- the multiple precision integer.
 * @param[in] bit			- the bit position to read.
 * @return the bit value.
 */
int relic_bn_get_bit(const relic_bn_t a, int bit);

/**
 * Stores a bit in a given position on a multiple precision integer.
 *
 * @param[out] a			- the multiple precision integer.
 * @param[in] bit			- the bit position to store.
 * @param[in] value			- the bit value.
 */
void relic_bn_set_bit(relic_bn_t a, int bit, int value);

/**
 * Returns the Hamming weight of a multiple precision integer.
 *
 * @param[in] a				- the multiple precision integer.
 * @return the number of non-zero bits.
 */
int relic_bn_ham(const relic_bn_t a);

/**
 * Reads the first digit in a multiple precision integer.
 *
 * @param[out] digit		- the result.
 * @param[in] a				- the multiple precision integer.
 */
void relic_bn_get_dig(dig_t *digit, const relic_bn_t a);

/**
 * Assigns a small positive constant to a multiple precision integer.
 *
 * The constant must fit on a multiple precision digit, or dig_t type using
 * only the number of bits specified on RLC_DIG.
 *
 * @param[out] a			- the result.
 * @param[in] digit			- the constant to assign.
 */
void relic_bn_set_dig(relic_bn_t a, dig_t digit);

/**
 * Assigns a multiple precision integer to 2^b.
 *
 * @param[out] a			- the result.
 * @param[in] b				- the power of 2 to assign.
 */
void relic_bn_set_2b(relic_bn_t a, int b);

/**
 * Assigns a random value to a multiple precision integer.
 *
 * @param[out] a			- the multiple precision integer to assign.
 * @param[in] sign			- the sign to be assigned (RLC_NEG or RLC_POS).
 * @param[in] bits			- the number of bits.
 */
void relic_bn_rand(relic_bn_t a, int sign, int bits);

/**
 * Assigns a non-zero random value to a multiple precision integer with absolute
 * value smaller than a given modulus.
 *
 * @param[out] a			- the multiple precision integer to assign.
 * @param[in] b				- the modulus.
 */
void relic_bn_rand_mod(relic_bn_t a, relic_bn_t b);

/**
 * Prints a multiple precision integer to standard output.
 *
 * @param[in] a				- the multiple precision integer to print.
 */
void relic_bn_print(const relic_bn_t a);

/**
 * Returns the number of digits in radix necessary to store a multiple precision
 * integer. The radix must be included in the interval [2, 64].
 *
 * @param[in] a				- the multiple precision integer.
 * @param[in] radix			- the radix.
 * @throw ERR_NO_VALID		- if the radix is invalid.
 * @return the number of digits in the given radix.
 */
int relic_bn_size_str(const relic_bn_t a, int radix);

/**
 * Reads a multiple precision integer from a string in a given radix. The radix
 * must be included in the interval [2, 64].
 *
 * @param[out] a			- the result.
 * @param[in] str			- the string.
 * @param[in] len			- the size of the string.
 * @param[in] radix			- the radix.
 * @throw ERR_NO_VALID		- if the radix is invalid.
 */
void relic_bn_read_str(relic_bn_t a, const char *str, int len, int radix);

/**
 * Writes a multiple precision integer to a string in a given radix. The radix
 * must be included in the interval [2, 64].
 *
 * @param[out] str			- the string.
 * @param[in] len			- the buffer capacity.
 * @param[in] a				- the multiple integer to write.
 * @param[in] radix			- the radix.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is insufficient.
 * @throw ERR_NO_VALID		- if the radix is invalid.
 */
void relic_bn_write_str(char *str, int len, const relic_bn_t a, int radix);

/**
 * Returns the number of bytes necessary to store a multiple precision integer.
 *
 * @param[in] a				- the multiple precision integer.
 * @return the number of bytes.
 */
int relic_bn_size_bin(const relic_bn_t a);

/**
 * Reads a positive multiple precision integer from a byte vector in big-endian
 * format.
 *
 * @param[out] a			- the result.
 * @param[in] bin			- the byte vector.
 * @param[in] len			- the buffer capacity.
 */
void relic_bn_read_bin(relic_bn_t a, const uint8_t *bin, int len);

/**
 * Writes a positive multiple precision integer to a byte vector in big-endian
 * format.
 *
 * @param[out] bin			- the byte vector.
 * @param[in] len			- the buffer capacity.
 * @param[in] a				- the multiple integer to write.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is insufficient.
 */
void relic_bn_write_bin(uint8_t *bin, int len, const relic_bn_t a);

/**
 * Returns the number of digits necessary to store a multiple precision integer.
 *
 * @param[in] a				- the multiple precision integer.
 * @return the number of digits.
 */
int relic_bn_size_raw(const relic_bn_t a);

/**
 * Reads a positive multiple precision integer from a digit vector.
 *
 * @param[out] a			- the result.
 * @param[in] raw			- the digit vector.
 * @param[in] len			- the size of the string.
 */
void relic_bn_read_raw(relic_bn_t a, const dig_t *raw, int len);

/**
 * Writes a positive multiple precision integer to a byte vector.
 *
 * @param[out] raw			- the digit vector.
 * @param[in] len			- the buffer capacity.
 * @param[in] a				- the multiple integer to write.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is insufficient.
 */
void relic_bn_write_raw(dig_t *raw, int len, const relic_bn_t a);

/**
 * Returns the result of an unsigned comparison between two multiple precision
 * integers.
 *
 * @param[in] a				- the first multiple precision integer.
 * @param[in] b				- the second multiple precision integer.
 * @return RLC_LT if a < b, RLC_EQ if a == b and RLC_GT if a > b.
 */
int relic_bn_cmp_abs(const relic_bn_t a, const relic_bn_t b);

/**
 * Returns the result of a signed comparison between a multiple precision
 * integer and a digit.
 *
 * @param[in] a				- the multiple precision integer.
 * @param[in] b				- the digit.
 * @return RLC_LT if a < b, RLC_EQ if a == b and RLC_GT if a > b.
 */
int relic_bn_cmp_dig(const relic_bn_t a, dig_t b);

/**
 * Returns the result of a signed comparison between two multiple precision
 * integers.
 *
 * @param[in] a				- the first multiple precision integer.
 * @param[in] b				- the second multiple precision integer.
 * @return RLC_LT if a < b, RLC_EQ if a == b and RLC_GT if a > b.
 */
int relic_bn_cmp(const relic_bn_t a, const relic_bn_t b);

/**
 * Adds two multiple precision integers. Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first multiple precision integer to add.
 * @param[in] b				- the second multiple precision integer to add.
 */
void relic_bn_add(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Adds a multiple precision integers and a digit. Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to add.
 * @param[in] b				- the digit to add.
 */
void relic_bn_add_dig(relic_bn_t c, const relic_bn_t a, dig_t b);

/**
 * Subtracts a multiple precision integer from another, that is, computes
 * c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer.
 * @param[in] b				- the multiple precision integer to subtract.
 */
void relic_bn_sub(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Subtracts a digit from a multiple precision integer. Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer.
 * @param[in] b				- the digit to subtract.
 */
void relic_bn_sub_dig(relic_bn_t c, const relic_bn_t a, const dig_t b);

/**
 * Multiplies a multiple precision integer by a digit. Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to multiply.
 * @param[in] b				- the digit to multiply.
 */
void relic_bn_mul_dig(relic_bn_t c, const relic_bn_t a, dig_t b);

/**
 * Multiplies two multiple precision integers using Schoolbook multiplication.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first multiple precision integer to multiply.
 * @param[in] b				- the second multiple precision integer to multiply.
 */
void relic_bn_mul_basic(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Multiplies two multiple precision integers using Comba multiplication.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first multiple precision integer to multiply.
 * @param[in] b				- the second multiple precision integer to multiply.
 */
void relic_bn_mul_comba(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Multiplies two multiple precision integers using Karatsuba multiplication.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first multiple precision integer to multiply.
 * @param[in] b				- the second multiple precision integer to multiply.
 */
void relic_bn_mul_karat(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Computes the square of a multiple precision integer using Schoolbook
 * squaring.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to square.
 */
void relic_bn_sqr_basic(relic_bn_t c, const relic_bn_t a);

/**
 * Computes the square of a multiple precision integer using Comba squaring.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to square.
 */
void relic_bn_sqr_comba(relic_bn_t c, const relic_bn_t a);

/**
 * Computes the square of a multiple precision integer using Karatsuba squaring.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to square.
 */
void relic_bn_sqr_karat(relic_bn_t c, const relic_bn_t a);

/**
 * Doubles a multiple precision. Computes c = a + a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to double.
 */
void relic_bn_dbl(relic_bn_t c, const relic_bn_t a);

/**
 * Halves a multiple precision. Computes c = floor(a / 2)
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to halve.
 */
void relic_bn_hlv(relic_bn_t c, const relic_bn_t a);

/**
 * Shifts a multiple precision number to the left. Computes c = a * 2^bits.
 * c = a * 2^bits.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to shift.
 * @param[in] bits			- the number of bits to shift.
 */
void relic_bn_lsh(relic_bn_t c, const relic_bn_t a, int bits);

/**
 * Shifts a multiple precision number to the right. Computes
 * c = floor(a / 2^bits).
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to shift.
 * @param[in] bits			- the number of bits to shift.
 */
void relic_bn_rsh(relic_bn_t c, const relic_bn_t a, int bits);

/**
 * Divides a multiple precision integer by another multiple precision integer
 * without producing the positive remainder. Computes c = floor(a / b).
 *
 * @param[out] c			- the resulting quotient.
 * @param[in] a				- the dividend.
 * @param[in] b				- the divisor.
 * @throw ERR_NO_VALID		- if the divisor is zero.
 */
void relic_bn_div(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Divides a multiple precision integer by another multiple precision integer
 * and produces a positive remainder. Computes c = floor(a / b) and d = a mod b.
 *
 * @param[out] c			- the resulting quotient.
 * @param[out] d			- the positive remainder.
 * @param[in] a				- the dividend.
 * @param[in] b				- the divisor.
 * @throw ERR_NO_VALID		- if the divisor is zero.
 */
void relic_bn_div_rem(relic_bn_t c, relic_bn_t d, const relic_bn_t a, const relic_bn_t b);

/**
 * Divides a multiple precision integers by a digit without computing the
 * remainder. Computes c = floor(a / b).
 *
 * @param[out] c			- the resulting quotient.
 * @param[out] d			- the remainder.
 * @param[in] a				- the dividend.
 * @param[in] b				- the divisor.
 * @throw ERR_NO_VALID		- if the divisor is zero.
 */
void relic_bn_div_dig(relic_bn_t c, const relic_bn_t a, dig_t b);

/**
 * Divides a multiple precision integers by a digit. Computes c = floor(a / b)
 * and d = a mod b.
 *
 * @param[out] c			- the resulting quotient.
 * @param[out] d			- the remainder.
 * @param[in] a				- the dividend.
 * @param[in] b				- the divisor.
 * @throw ERR_NO_VALID		- if the divisor is zero.
 */
void relic_bn_div_rem_dig(relic_bn_t c, dig_t *d, const relic_bn_t a, const dig_t b);

/**
 * Reduces a multiple precision integer modulo a power of 2. Computes
 * c = a mod 2^b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the dividend.
 * @param[in] b				- the exponent of the divisor.
 */
void relic_bn_mod_2b(relic_bn_t c, const relic_bn_t a, int b);

/**
 * Reduces a multiple precision integer modulo a digit. Computes c = a mod b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the dividend.
 * @param[in] b				- the divisor.
 */
void relic_bn_mod_dig(dig_t *c, const relic_bn_t a, dig_t b);

/**
 * Reduces a multiple precision integer modulo an integer using straightforward
 * division.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to reduce.
 * @param[in] m				- the modulus.
 */
void relic_bn_mod_basic(relic_bn_t c, const relic_bn_t a, const relic_bn_t m);

/**
 * Computes the reciprocal of the modulus to be used in the Barrett modular
 * reduction algorithm.
 *
 * @param[out] u			- the result.
 * @param[in] m				- the modulus.
 */
void relic_bn_mod_pre_barrt(relic_bn_t u, const relic_bn_t m);

/**
 * Reduces a multiple precision integer modulo a positive integer using Barrett
 * reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the the multiple precision integer to reduce.
 * @param[in] m				- the modulus.
 * @param[in] u				- the reciprocal of the modulus.
 */
void relic_bn_mod_barrt(relic_bn_t c, const relic_bn_t a, const relic_bn_t m, const relic_bn_t u);

/**
 * Computes the reciprocal of the modulus to be used in the Montgomery reduction
 * algorithm.
 *
 * @param[out] u			- the result.
 * @param[in] m				- the modulus.
 * @throw ERR_NO_VALID		- if the modulus is even.
 */
void relic_bn_mod_pre_monty(relic_bn_t u, const relic_bn_t m);

/**
 * Converts a multiple precision integer to Montgomery form.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to convert.
 * @param[in] m				- the modulus.
 */
void relic_bn_mod_monty_conv(relic_bn_t c, const relic_bn_t a, const relic_bn_t m);

/**
 * Converts a multiple precision integer from Montgomery form.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to convert.
 * @param[in] m				- the modulus.
 */
void relic_bn_mod_monty_back(relic_bn_t c, const relic_bn_t a, const relic_bn_t m);

/**
 * Reduces a multiple precision integer modulo a positive integer using
 * Montgomery reduction with Schoolbook multiplication.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to reduce.
 * @param[in] m				- the modulus.
 * @param[in] u				- the reciprocal of the modulus.
 */
void relic_bn_mod_monty_basic(relic_bn_t c, const relic_bn_t a, const relic_bn_t m, const relic_bn_t u);

/**
 * Reduces a multiple precision integer modulo a positive integer using
 * Montgomery reduction with Comba multiplication.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to reduce.
 * @param[in] m				- the modulus.
 * @param[in] u				- the reciprocal of the modulus.
 */
void relic_bn_mod_monty_comba(relic_bn_t c, const relic_bn_t a, const relic_bn_t m, const relic_bn_t u);

/**
 * Computes u if the modulus has the form 2^b - u.
 *
 * @param[out] u			- the result.
 * @param[in] m				- the modulus.
 */
void relic_bn_mod_pre_pmers(relic_bn_t u, const relic_bn_t m);

/**
 * Reduces a multiple precision integer modulo a positive integer using
 * pseudo-Mersenne modular reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to reduce.
 * @param[in] m				- the modulus.
 * @param[in] u				- the auxiliar value derived from the modulus.
 */
void relic_bn_mod_pmers(relic_bn_t c, const relic_bn_t a, const relic_bn_t m, const relic_bn_t u);

/**
 * Exponentiates a multiple precision integer modulo a positive integer using
 * the binary method.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the basis.
 * @param[in] b				- the exponent.
 * @param[in] m				- the modulus.
 */
void relic_bn_mxp_basic(relic_bn_t c, const relic_bn_t a, const relic_bn_t b, const relic_bn_t m);

/**
 * Exponentiates a multiple precision integer modulo a positive integer using
 * the sliding window method.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the basis.
 * @param[in] b				- the exponent.
 * @param[in] m				- the modulus.
 */
void relic_bn_mxp_slide(relic_bn_t c, const relic_bn_t a, const relic_bn_t b, const relic_bn_t m);

/**
 * Exponentiates a multiple precision integer modulo a positive integer using
 * the constant-time Montgomery powering ladder method.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the basis.
 * @param[in] b				- the exponent.
 * @param[in] m				- the modulus.
 */
void relic_bn_mxp_monty(relic_bn_t c, const relic_bn_t a, const relic_bn_t b, const relic_bn_t m);

/**
 * Exponentiates a multiple precision integer by a small power modulo a positive
 * integer using the binary method.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the basis.
 * @param[in] b				- the exponent.
 * @param[in] m				- the modulus.
 */
void relic_bn_mxp_dig(relic_bn_t c, const relic_bn_t a, dig_t b, const relic_bn_t m);

/**
 * Extracts an approximate integer square-root of a multiple precision integer.
 *
 * @param[out] c 			- the result.
 * @param[in] a 			- the multiple precision integer to extract.
 *
 * @throw ERR_NO_VALID		- if the argument is negative.
 */
void relic_bn_srt(relic_bn_t c, relic_bn_t a);

/**
 * Computes the greatest common divisor of two multiple precision integers
 * using the standard Euclidean algorithm.
 *
 * @param[out] c			- the result;
 * @param[in] a				- the first multiple precision integer.
 * @param[in] b				- the second multiple precision integer.
 */
void relic_bn_gcd_basic(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Computes the greatest common divisor of two multiple precision integers
 * using Lehmer's GCD algorithm.
 *
 * @param[out] c			- the result;
 * @param[in] a				- the first multiple precision integer.
 * @param[in] b				- the second multiple precision integer.
 */
void relic_bn_gcd_lehme(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Computes the greatest common divisor of two multiple precision integers
 * using Stein's binary GCD algorithm.
 *
 * @param[out] c			- the result;
 * @param[in] a				- the first multiple precision integer.
 * @param[in] b				- the second multiple precision integer.
 */
void relic_bn_gcd_stein(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Computes the greatest common divisor of a multiple precision integer and a
 * digit.
 *
 * @param[out] c			- the result;
 * @param[in] a				- the multiple precision integer.
 * @param[in] b				- the digit.
 */
void relic_bn_gcd_dig(relic_bn_t c, const relic_bn_t a, dig_t b);

/**
 * Computes the extended greatest common divisor of two multiple precision
 * integer using the Euclidean algorithm.
 *
 * @param[out] c			- the result.
 * @param[out] d			- the cofactor of the first operand, can be NULL.
 * @param[out] e			- the cofactor of the second operand, can be NULL.
 * @param[in] a				- the first multiple precision integer.
 * @param[in] b				- the second multiple precision integer.
 */
void relic_bn_gcd_ext_basic(relic_bn_t c, relic_bn_t d, relic_bn_t e, const relic_bn_t a, const relic_bn_t b);

/**
 * Computes the greatest common divisor of two multiple precision integers
 * using Lehmer's algorithm.
 *
 * @param[out] c			- the result;
 * @param[out] d			- the cofactor of the first operand, can be NULL.
 * @param[out] e			- the cofactor of the second operand, can be NULL.
 * @param[in] a				- the first multiple precision integer.
 * @param[in] b				- the second multiple precision integer.
 */
void relic_bn_gcd_ext_lehme(relic_bn_t c, relic_bn_t d, relic_bn_t e, const relic_bn_t a, const relic_bn_t b);

/**
 * Computes the greatest common divisor of two multiple precision integers
 * using Stein's binary algorithm.
 *
 * @param[out] c			- the result;
 * @param[out] d			- the cofactor of the first operand, can be NULL.
 * @param[out] e			- the cofactor of the second operand, can be NULL.
 * @param[in] a				- the first multiple precision integer.
 * @param[in] b				- the second multiple precision integer.
 */
void relic_bn_gcd_ext_stein(relic_bn_t c, relic_bn_t d, relic_bn_t e, const relic_bn_t a, const relic_bn_t b);

/**
 * Computes the extended greatest common divisor of two multiple precision
 * integers halfway through the algorithm. Returns also two short vectors
 * v1 = (c, d), v2 = (-e, f) useful to decompose an integer k into k0, k1 such
 * that k = k_0 + k_1 * a (mod b).
 *
 * @param[out] c			- the first component of the first vector.
 * @param[out] d			- the second component of the first vector.
 * @param[out] e			- the first component of the second vector.
 * @param[out] f			- the second component of the second vector.
 * @param[in] a				- the first multiple precision integer.
 * @param[in] b				- the second multiple precision integer.
 */
void relic_bn_gcd_ext_mid(relic_bn_t c, relic_bn_t d, relic_bn_t e, relic_bn_t f, const relic_bn_t a, const relic_bn_t b);

/**
 * Computes the extended greatest common divisor of a multiple precision integer
 * and a digit.
 *
 * @param[out] c			- the result.
 * @param[out] d			- the cofactor of the first operand, can be NULL.
 * @param[out] e			- the cofactor of the second operand, can be NULL.
 * @param[in] a				- the multiple precision integer.
 * @param[in] b				- the digit.
 */
void relic_bn_gcd_ext_dig(relic_bn_t c, relic_bn_t d, relic_bn_t e, const relic_bn_t a, dig_t b);

/**
 * Computes the last common multiple of two multiple precision integers.
 * Computes c = lcm(a, b).
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first integer.
 * @param[in] b				- the second integer.
 */
void relic_bn_lcm(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Computes the Legendre symbol c = (a|b), b prime.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first parameter.
 * @param[in] b				- the second parameter.
 */
void relic_bn_smb_leg(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Computes the Jacobi symbol c = (a|b).
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first parameter.
 * @param[in] b				- the second parameter.
 */
void relic_bn_smb_jac(relic_bn_t c, const relic_bn_t a, const relic_bn_t b);

/**
 * Returns a small precomputed prime from a given position in the list of prime
 * numbers.
 *
 * @param[in] pos			- the position in the prime sequence.
 * @return a prime if the position is lower than 512, 0 otherwise.
 */
dig_t relic_bn_get_prime(int pos);

/**
 * Tests if a number is a probable prime.
 *
 * @param[in] a				- the multiple precision integer to test.
 * @return 1 if a is prime, 0 otherwise.
 */
int relic_bn_is_prime(const relic_bn_t a);

/**
 * Tests if a number is prime using a series of trial divisions.
 *
 * @param[in] a				- the number to test.
 * @return 1 if a is a probable prime, 0 otherwise.
 */
int relic_bn_is_prime_basic(const relic_bn_t a);

/**
 * Tests if a number a > 2 is prime using the Miller-Rabin test with probability
 * 2^(-80) of error.
 *
 * @param[in] a				- the number to test.
 * @return 1 if a is a probable prime, 0 otherwise.
 */
int relic_bn_is_prime_rabin(const relic_bn_t a);

/**
 * Tests if a number a > 2 is prime using the Solovay-Strassen test with
 * probability 2^(-80) of error.
 *
 * @param[in] a				- the number to test.
 * @return 1 if a is a probable prime, 0 otherwise.
 */
int relic_bn_is_prime_solov(const relic_bn_t a);

/**
 * Generates a probable prime number.
 *
 * @param[out] a			- the result.
 * @param[in] bits			- the length of the number in bits.
 */
void relic_bn_gen_prime_basic(relic_bn_t a, int bits);

/**
 * Generates a probable prime number a with (a - 1)/2 also prime.
 *
 * @param[out] a			- the result.
 * @param[in] bits			- the length of the number in bits.
 */
void relic_bn_gen_prime_safep(relic_bn_t a, int bits);

/**
 * Generates a probable prime number with (a - 1)/2, (a + 1)/2 and
 * ((a - 1)/2 - 1)/2 also prime.
 *
 * @param[out] a			- the result.
 * @param[in] bits			- the length of the number in bits.
 */
void relic_bn_gen_prime_stron(relic_bn_t a, int bits);

/**
 * Tries to factorize an integer using Pollard (p - 1) factoring algorithm.
 * The maximum length of the returned factor is 16 bits.
 *
 * @param[out] c			- the resulting factor.
 * @param[in] a				- the integer to fatorize.
 * @return 1 if a factor is found and stored into c; 0 otherwise.
 */
int relic_bn_factor(relic_bn_t c, const relic_bn_t a);

/**
 * Tests if an integer divides other integer.
 *
 * @param[in] c				- the factor.
 * @param[in] a				- the integer.
 * @return 1 if the first integer is a factor; 0 otherwise.
 */
int relic_bn_is_factor(relic_bn_t c, const relic_bn_t a);

/**
 * Recodes a positive integer in window form. If a negative integer is given
 * instead, its absolute value is taken.
 *
 * @param[out] win			- the recoded integer.
 * @param[out] len			- the number of bytes written.
 * @param[in] k				- the integer to recode.
 * @param[in] w				- the window size in bits.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is insufficient.
 */
void relic_bn_rec_win(uint8_t *win, int *len, const relic_bn_t k, int w);

/**
 * Recodes a positive integer in sliding window form. If a negative integer is
 * given instead, its absolute value is taken.
 *
 * @param[out] win			- the recoded integer.
 * @param[out] len			- the number of bytes written.
 * @param[in] k				- the integer to recode.
 * @param[in] w				- the window size in bits.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is insufficient.
 */
void relic_bn_rec_slw(uint8_t *win, int *len, const relic_bn_t k, int w);

/**
 * Recodes a positive integer in width-w Non-Adjacent Form. If a negative
 * integer is given instead, its absolute value is taken.
 *
 * @param[out] naf			- the recoded integer.
 * @param[out] len			- the number of bytes written.
 * @param[in] k				- the integer to recode.
 * @param[in] w				- the window size in bits.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is insufficient.
 */
void relic_bn_rec_naf(int8_t *naf, int *len, const relic_bn_t k, int w);

/**
 * Recodes a positive integer in width-w \tau-NAF. If a negative integer is
 * given instead, its absolute value is taken.
 *
 * @param[out] tnaf			- the recoded integer.
 * @param[out] len			- the number of bytes written.
 * @param[in] k				- the integer to recode.
 * @param[in] u				- the u curve parameter.
 * @param[in] m				- the extension degree of the binary field.
 * @param[in] w				- the window size in bits.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is insufficient.
 */
void relic_bn_rec_tnaf(int8_t *tnaf, int *len, const relic_bn_t k, int8_t u, int m, int w);

/**
 * Recodes a positive integer in regular fixed-length width-w \tau-NAF.
 * If a negative integer is given instead, its absolute value is taken.
 *
 * @param[out] tnaf			- the recoded integer.
 * @param[out] len			- the number of bytes written.
 * @param[in] k				- the integer to recode.
 * @param[in] u				- the u curve parameter.
 * @param[in] m				- the extension degree of the binary field.
 * @param[in] w				- the window size in bits.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is insufficient.
 */
void relic_bn_rec_rtnaf(int8_t *tnaf, int *len, const relic_bn_t k, int8_t u, int m, int w);

/**
 * Write the constants needed for \tau-NAF recoding as a set of \alpha_u =
 * \beta_u + \gamma_u * \tau elements.
 *
 * @param[out] t 		- the integer corresponding to \tau.
 * @param[out] beta		- the first coefficients of the constants.
 * @param[out] gama		- the second coefficients of the constants.
 * @param[in] u 		- the u curve parameter.
 * @param[in] w 		- the window size in bits.
 */
void relic_bn_rec_tnaf_get(uint8_t *t, int8_t *beta, int8_t *gama, int8_t u, int w);

/**
 * Computes the partial reduction k partmod d = r0 + r1 * t, where
 * d = (t^m - 1)/(t - 1).
 *
 * @param[out] r0		- the first half of the result.
 * @param[out] r1		- the second half of the result.
 * @param[in] k			- the number to reduce.
 * @param[in] u			- the u curve parameter.
 * @param[in] m			- the extension degree of the binary field.
 */
void relic_bn_rec_tnaf_mod(relic_bn_t r0, relic_bn_t r1, const relic_bn_t k, int u, int m);

/**
 * Recodes a positive integer in regular fixed-length width-w NAF. If a negative
 * integer is given instead, its absolute value is taken.
 *
 * @param[out] naf			- the recoded integer.
 * @param[out] len			- the number of bytes written.
 * @param[in] k				- the integer to recode.
 * @param[in] n				- the length of the recoding.
 * @param[in] w				- the window size in bits.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is insufficient.
 */
void relic_bn_rec_reg(int8_t *naf, int *len, const relic_bn_t k, int n, int w);

/**
 * Recodes of a pair of positive integers in Joint Sparse Form. If negative
 * integers are given instead, takes their absolute value.
 *
 * @param[out] jsf			- the recoded pair of integers.
 * @param[out] len			- the number of bytes written.
 * @param[in] k				- the first integer to recode.
 * @param[in] l				- the second integer to recode.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is insufficient.
 */
void relic_bn_rec_jsf(int8_t *jsf, int *len, const relic_bn_t k, const relic_bn_t l);

/**
 * Recodes a positive integer into two parts k0,k1 such that k = k0 + phi(k1),
 * where phi is an efficient curve endomorphism. If a negative integer is
 * given instead, its absolute value is taken.
 *
 * @param[out] k0			- the first part of the result.
 * @param[out] k1			- the second part of the result.
 * @param[in] k				- the integer to recode.
 * @param[in] n				- the group order.
 * @param[in] v1			- the set of parameters v1 for the GLV method.
 * @param[in] v2			- the set of parameters v2 for the GLV method.
 */
void relic_bn_rec_glv(relic_bn_t k0, relic_bn_t k1, const relic_bn_t k, const relic_bn_t n, const relic_bn_t v1[],
		const relic_bn_t v2[]);

#endif /* !RLC_relic_bn_H */
