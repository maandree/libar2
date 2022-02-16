/* See LICENSE file for copyright and license details. */
#define WARN_UNKNOWN_ENDIAN
#include "common.h"


struct threaded_fill_segments_params {
	struct block *memory;
	const uint_least64_t *sbox;
	struct libar2_argon2_parameters *params;
	uint_least32_t seglen;
	uint_least32_t lanelen;
	uint_least32_t blocks;
	uint_least32_t pass;
	uint_least32_t lane;
	uint_least32_t slice;
};


static const struct libblake_blake2b_params b2params = {
	.digest_len = 64,
	.key_len = 0,
	.fanout = 1,
	.depth = 1,
	.leaf_len = 0,
	.node_offset = 0,
	.node_depth = 0,
	.inner_len = 0
};


static const struct block zerob; /* implicitly zeroed via `static` */


static void
memxor(void *a_, const void *b_, size_t n) /* TODO using _mm_xor_si128 may improve performance */
{
	unsigned char *a = a_;
	const unsigned char *b = b_;
	size_t i;
	for (i = 0; i < n; i++)
		a[i] ^= b[i];
}


static size_t
store32(unsigned char *out, uint_least32_t value)
{
	out[0] = (unsigned char)((value >> 0) & 255);
	out[1] = (unsigned char)((value >> 8) & 255);
	out[2] = (unsigned char)((value >> 16) & 255);
	out[3] = (unsigned char)((value >> 24) & 255);
	return 4;
}


#ifndef USING_LITTLE_ENDIAN

static void
store64(unsigned char *out, uint_least64_t value)
{
	out[0] = (unsigned char)((value >> 0) & 255);
	out[1] = (unsigned char)((value >> 8) & 255);
	out[2] = (unsigned char)((value >> 16) & 255);
	out[3] = (unsigned char)((value >> 24) & 255);
	out[4] = (unsigned char)((value >> 32) & 255);
	out[5] = (unsigned char)((value >> 40) & 255);
	out[6] = (unsigned char)((value >> 48) & 255);
	out[7] = (unsigned char)((value >> 56) & 255);
}


static void
load64(uint_least64_t *out, const unsigned char *data)
{
	*out = ((uint_least64_t)(data[0] & 255) << 0)
	     | ((uint_least64_t)(data[1] & 255) << 8)
	     | ((uint_least64_t)(data[2] & 255) << 16)
	     | ((uint_least64_t)(data[3] & 255) << 24)
	     | ((uint_least64_t)(data[4] & 255) << 32)
	     | ((uint_least64_t)(data[5] & 255) << 40)
	     | ((uint_least64_t)(data[6] & 255) << 48)
	     | ((uint_least64_t)(data[7] & 255) << 56);
}


static void
store_block(unsigned char *block8, const struct block *block64)
{
	size_t i, j;
	for (i = 0, j = 0; i < 1024; i += 8, j += 1)
		store64(&block8[i], block64->w[j]);
}


static void
load_block(struct block *block64, const unsigned char *block8)
{
	size_t i, j;
	for (i = 0, j = 0; i < 1024; i += 8, j += 1)
		load64(&block64->w[j], &block8[i]);
}

#endif


static size_t
storemem(unsigned char *out, const void *mem, size_t len, size_t max)
{
	size_t n = MIN(len, max);
	memcpy(out, mem, n);
	return n;
}


static uint_least64_t
rotr64(uint_least64_t x, int n)
{
	return ((x >> n) | (x << (64 - n))) & UINT_LEAST64_C(0xFFFFffffFFFFffff);
}


static uint_least64_t
fBlaMka(uint_least64_t x, uint_least64_t y)
{
	return x + y + 2 * (x & UINT_LEAST64_C(0xFFffFFff)) * (y & UINT_LEAST64_C(0xFFffFFff));
}


static void
fill_block(struct block *block, const struct block *prevblock, const struct block *refblock,
           int with_xor, const uint_least64_t *sbox)
{
	uint_least64_t x = 0;
	uint_least32_t x_hi, x_lo;
	struct block tmpblock;
	size_t i;

	if (with_xor) {
		for (i = 0; i < ELEMSOF(refblock->w); i++)
			block->w[i] ^= tmpblock.w[i] = refblock->w[i] ^ prevblock->w[i];
	} else {
		for (i = 0; i < ELEMSOF(refblock->w); i++)
			block->w[i] = tmpblock.w[i] = refblock->w[i] ^ prevblock->w[i];
	}

	if (sbox) {
		x = tmpblock.w[0] ^ tmpblock.w[ELEMSOF(tmpblock.w) - 1];
		for (i = 0; i < 96; i++) {
			x_hi = (uint_least32_t)(x >> 32);
			x_lo = (uint_least32_t)x & UINT_LEAST32_C(0xFFFFffff);
			x = (uint_least64_t)x_hi * (uint_least64_t)x_lo;
			x += sbox[(x_hi & UINT_LEAST32_C(0x1FF)) + 0];
			x ^= sbox[(x_lo & UINT_LEAST32_C(0x1FF)) + 512];
		}
	}

#define BLAMKA_G(A, B, C, D)\
	A = fBlaMka(A, B);\
	D = rotr64(D ^ A, 32);\
	C = fBlaMka(C, D);\
	B = rotr64(B ^ C, 24);\
	A = fBlaMka(A, B);\
	D = rotr64(D ^ A, 16);\
	C = fBlaMka(C, D);\
	B = rotr64(B ^ C, 63)

#define BLAMKA_ROUND(W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, WA, WB, WC, WD, WE, WF)\
	BLAMKA_G(W0, W4, W8, WC);\
	BLAMKA_G(W1, W5, W9, WD);\
	BLAMKA_G(W2, W6, WA, WE);\
	BLAMKA_G(W3, W7, WB, WF);\
	BLAMKA_G(W0, W5, WA, WF);\
	BLAMKA_G(W1, W6, WB, WC);\
	BLAMKA_G(W2, W7, W8, WD);\
	BLAMKA_G(W3, W4, W9, WE)

#define BLAMKA_ROUND_(ARR, OFF, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, WA, WB, WC, WD, WE, WF)\
	BLAMKA_ROUND(ARR[OFF + W0], ARR[OFF + W1], ARR[OFF + W2], ARR[OFF + W3],\
	             ARR[OFF + W4], ARR[OFF + W5], ARR[OFF + W6], ARR[OFF + W7],\
	             ARR[OFF + W8], ARR[OFF + W9], ARR[OFF + WA], ARR[OFF + WB],\
	             ARR[OFF + WC], ARR[OFF + WD], ARR[OFF + WE], ARR[OFF + WF])

	for (i = 0; i < 8; i++) {
		BLAMKA_ROUND_(tmpblock.w, i * 16,
		               0,  1,  2,  3,
		               4,  5,  6,  7,
		               8,  9, 10, 11,
		              12, 13, 14, 15);
	}
	for (i = 0; i < 8; i++) {
		BLAMKA_ROUND_(tmpblock.w, i * 2,
		               0,  1, 16, 17,
		              32, 33, 48, 49,
		              64, 65, 80, 81,
		              96, 97, 112, 113);
	}

	for (i = 0; i < ELEMSOF(refblock->w); i++)
		block->w[i] ^= tmpblock.w[i];

	block->w[0] += x;
	block->w[ELEMSOF(block->w) - 1] += x;
	block->w[0] &= UINT_LEAST64_C(0xFFFFffffFFFFffff);
	block->w[ELEMSOF(block->w) - 1] &= UINT_LEAST64_C(0xFFFFffffFFFFffff);
}


static void
generate_sbox(uint_least64_t *sbox, struct block *memory)
{
	void *next, *prev = memory;
	size_t i;

	for (i = 0; i < 8; i++) {
		next = &sbox[i * 128];
		fill_block(next, &zerob, prev, 0, NULL);
		fill_block(next, &zerob, next, 0, NULL);
		prev = next;
	}
}


static void
next_address_block(struct block *addrb, struct block *inputb)
{
	inputb->w[6] += 1;
	fill_block(addrb, &zerob, inputb, 0, NULL);
	fill_block(addrb, &zerob, addrb, 0, NULL);
}


static uint_least32_t
get_rindex(uint_least32_t seglen, uint_least32_t lanelen, uint_least32_t pass,
           uint_least32_t slice, uint_least32_t index, uint_least64_t prand, int same_lane)
{
	uint_least32_t size, startpos;
	uint_least64_t relpos;

	if (!pass) {
		if (!slice)
			size = index - 1;
		else if (same_lane)
			size = slice * seglen + index - 1;
		else
			size = slice * seglen - !index;
	} else {
		if (same_lane)
			size = lanelen - seglen + index - 1;
		else
			size = lanelen - seglen - !index;
	}

	prand &= UINT_LEAST64_C(0xFFffFFff);
	relpos = (prand * prand) >> 32;
	relpos = ((uint_least64_t)size * relpos) >> 32;
	relpos = (uint_least64_t)size - 1 - relpos;

	startpos = pass ? slice == 3 ? 0 : (slice + 1) * seglen : 0;

	return (startpos + (uint_least32_t)relpos) % lanelen;
}


static void
fill_segment(struct block *memory, const uint_least64_t *sbox, struct libar2_argon2_parameters *params,
             uint_least32_t seglen, uint_least32_t lanelen, uint_least32_t blocks,
	     uint_least32_t pass, uint_least32_t lane, uint_least32_t slice)
{
	int data_independent;
	struct block inputb, addrb;
	uint_least32_t off, prevoff, rlane, rindex;
	uint_least32_t index = 0, i;
	uint_least64_t prand;

	data_independent =
		(params->type == LIBAR2_ARGON2I) ||
		(params->type == LIBAR2_ARGON2ID && !pass && slice < 2);

	if (data_independent) {
		memset(&inputb.w[6], 0, sizeof(*inputb.w) * (ELEMSOF(inputb.w) - 6));
		inputb.w[0] = pass;
		inputb.w[1] = lane;
		inputb.w[2] = slice;
		inputb.w[3] = blocks;
		inputb.w[4] = params->t_cost;
		inputb.w[5] = (uint_least32_t)params->type;
		if (!pass && !slice) {
			next_address_block(&addrb, &inputb);
			index = 2;
		}
	} else if (!pass && !slice) {
		index = 2;
	}

	off = lane * lanelen + slice * seglen + index;
	prevoff = off - 1 + (off % lanelen ? 0 : lanelen);

	for (; index < seglen; index++, off++, prevoff++) {
		if (off % lanelen == 1)
			prevoff = off - 1;
		if (data_independent) {
			i = index % ELEMSOF(addrb.w);
			if (!i)
				next_address_block(&addrb, &inputb);
			prand = addrb.w[i];
		} else {
			prand = memory[prevoff].w[0];
		}

		rlane = (!pass && !slice) ? lane : (uint_least32_t)(prand >> 32) % params->lanes;
		rindex = get_rindex(seglen, lanelen, pass, slice, index, prand, rlane == lane);

		fill_block(&memory[off], &memory[prevoff], &memory[rlane * lanelen + rindex],
		           params->version > LIBAR2_ARGON2_VERSION_10 && pass, sbox);
	}
}


static void
threaded_fill_segment(void *data)
{
	struct threaded_fill_segments_params *tparams = data;
	fill_segment(tparams->memory, tparams->sbox, tparams->params,
	             tparams->seglen, tparams->lanelen, tparams->blocks,
	             tparams->pass, tparams->lane, tparams->slice);
}


static void
initial_hash(unsigned char hash[static 64], void *msg, size_t msglen,
             struct libar2_argon2_parameters *params, struct libar2_context *ctx)
{
#define SEGMENT(DATA, LEN, OFF) &((const unsigned char *)(DATA))[(OFF)], (LEN) - (OFF)

	struct libblake_blake2b_state state;
	unsigned char block[128 + 3];
	size_t n = 0, off;

	libblake_blake2b_init(&state, &b2params, NULL);

	n += store32(&block[n], params->lanes);
	n += store32(&block[n], (uint_least32_t)params->hashlen);
	n += store32(&block[n], params->m_cost);
	n += store32(&block[n], params->t_cost);
	n += store32(&block[n], (uint_least32_t)(params->version ? params->version : LIBAR2_ARGON2_VERSION_10));
	n += store32(&block[n], (uint_least32_t)params->type);
	n += store32(&block[n], (uint_least32_t)msglen);
	if (msglen) {
		n += off = storemem(&block[n], msg, msglen, 128 - n);
		if (n == 128) {
			libblake_blake2b_force_update(&state, block, n);
			n = 0;
			if (off < msglen) {
				off += libblake_blake2b_force_update(&state, SEGMENT(msg, msglen, off));
				memcpy(block, SEGMENT(msg, msglen, off));
				n = msglen - off;
			}
		}
		if (ctx->autoerase_message)
			ERASE(msg, msglen);
	}

	n += store32(&block[n], (uint_least32_t)params->saltlen);
	if (n >= 128) {
		n -= libblake_blake2b_force_update(&state, block, n);
		memcpy(block, &block[128], n); /* overlap is impossible */
	}
	if (params->saltlen) {
		if (!n)
			off = 0;
		else
			n += off = storemem(&block[n], params->salt, params->saltlen, 128 - n);
		if (n == 128) {
			libblake_blake2b_force_update(&state, block, n);
			n = 0;
		}
		if (n == 0 && off < params->saltlen) {
			off += libblake_blake2b_force_update(&state, SEGMENT(params->salt, params->saltlen, off));
			memcpy(block, SEGMENT(params->salt, params->saltlen, off));
			n = params->saltlen - off;
		}
		if (ctx->autoerase_salt)
			ERASE(params->salt, params->saltlen);
	}

	n += store32(&block[n], (uint_least32_t)params->keylen);
	if (n >= 128) {
		n -= libblake_blake2b_force_update(&state, block, n);
		memcpy(block, &block[128], n); /* overlap is impossible */
	}
	if (params->keylen) {
		if (!n)
			off = 0;
		else
			n += off = storemem(&block[n], params->key, params->keylen, 128 - n);
		if (n == 128) {
			libblake_blake2b_force_update(&state, block, n);
			n = 0;
		}
		if (n == 0 && off < params->keylen) {
			off += libblake_blake2b_force_update(&state, SEGMENT(params->key, params->keylen, off));
			memcpy(block, SEGMENT(params->key, params->keylen, off));
			n = params->keylen - off;
		}
		if (ctx->autoerase_secret)
			ERASE(params->key, params->keylen);
	}

	n += store32(&block[n], (uint_least32_t)params->adlen);
	if (n > 128 || (n == 128 && params->adlen)) {
		n -= libblake_blake2b_force_update(&state, block, n);
		memcpy(block, &block[128], n); /* overlap is impossible */
	}
	if (params->adlen) {
		if (!n)
			off = 0;
		else
			n += off = storemem(&block[n], params->ad, params->adlen, 128 - n);
		if (off < params->adlen) {
			if (n == 128) {
				libblake_blake2b_force_update(&state, block, n);
				n = 0;
			}
			if (n == 0) {
				off += libblake_blake2b_update(&state, SEGMENT(params->ad, params->adlen, off));
				if (params->adlen - off > 128) {
					/* $covered{$ (not really possible, but just to be safe) */
					off += libblake_blake2b_force_update(&state, SEGMENT(params->ad, params->adlen, off));
					/* $covered}$ */
				}
				memcpy(block, SEGMENT(params->ad, params->adlen, off));
				n = params->adlen - off;
			}
		}
		if (ctx->autoerase_associated_data)
			ERASE(params->ad, params->adlen);
	}

	libblake_blake2b_digest(&state, block, n, 0, 64, hash);

	ERASE_ARRAY(block);
	ERASE_STRUCT(state);

#undef SEGMENT
}


static void /* this is not BLAKE2Xb, but something Argon2-specific */
argon2_blake2b_exthash(void *hash_, size_t hashlen, void *msg_, size_t msglen)
{
	struct libblake_blake2b_params params;
	struct libblake_blake2b_state state;
	unsigned char *msg = msg_;
	unsigned char block[128];
	unsigned char *hash = hash_;
	size_t n, off;

	params = b2params;
	params.digest_len = (uint_least8_t)MIN(hashlen, (size_t)params.digest_len);

	libblake_blake2b_init(&state, &params, NULL);
	n = store32(block, (uint_least32_t)hashlen);
	n += off = storemem(&block[n], msg, msglen, 128 - n);
	if (off == msglen) {
		libblake_blake2b_digest(&state, block, n, 0, params.digest_len, hash);
	} else {
		libblake_blake2b_force_update(&state, block, 128);
		libblake_blake2b_digest(&state, &msg[off], msglen - off, 0, params.digest_len, hash);
	}

	if (hashlen > 64) {
		hashlen -= 32;
		params.digest_len = 64;
		while (hashlen > 64) {
			libblake_blake2b_init(&state, &params, NULL);
			libblake_blake2b_digest(&state, hash, 64, 0, 64, &hash[32]);
			hash += 32;
			hashlen -= 32;
		}
		params.digest_len = (uint_least8_t)hashlen;
		libblake_blake2b_init(&state, &params, NULL);
		libblake_blake2b_digest(&state, hash, 64, 0, hashlen, &hash[32]);
	}

	ERASE_STRUCT(state);
	ERASE_ARRAY(block);
}


int
libar2_hash(void *hash, void *msg, size_t msglen, struct libar2_argon2_parameters *params, struct libar2_context *ctx)
{
#ifndef USING_LITTLE_ENDIAN
	unsigned char block[1024 + 128];
#endif
	unsigned char hash0[256];
	uint_least32_t blocks, seglen, lanelen;
	struct block *memory;
	size_t i, p, s, nthreads, ts[16], ti, tn, bufsize;
	struct threaded_fill_segments_params *tparams = NULL;
	uint_least64_t *sbox = NULL; /* This is 8K large (assuming support for uint64_t), so we allocate it dynamically */

	if (libar2_validate_params(params, NULL) || msglen >> 31 > 1) {
		errno = EINVAL;
		return -1;
	}

	blocks = MAX(params->m_cost, 8 * params->lanes); /* 8 * params->lanes <= 0x07FFfff8 */
	seglen = blocks / (4 * params->lanes);
	blocks -= blocks % (4 * params->lanes);
	lanelen = seglen * 4;

#ifdef USING_LITTLE_ENDIAN
	/* We are allocating one extra block, this gives use 1024 extra bytes,
	 * but we only need 128, to ensure that `argon2_blake2b_exthash` does
	 * not write on unallocated memory. Preferable we would just request
	 * 128 bytes bytes, but this would require an undesirable API/ABI
	 * change. */
	memory = ctx->allocate(blocks + 1, sizeof(struct block), MAX(MAX(ALIGNOF(struct block), CACHE_LINE_SIZE), 16), ctx);
#else
	memory = ctx->allocate(blocks, sizeof(struct block), MAX(MAX(ALIGNOF(struct block), CACHE_LINE_SIZE), 16), ctx);
#endif
	if (!memory)
		return -1;

	if (params->type == LIBAR2_ARGON2DS) {
		sbox = ctx->allocate(1024, sizeof(*sbox), ALIGNOF(uint_least64_t), ctx);
		if (!sbox) {
			ctx->deallocate(memory, ctx);
			return -1;
		}
	}

	initial_hash(hash0, msg, msglen, params, ctx);
	for (i = 0; i < params->lanes; i++) { /* direction is important for little-endian optimisation */
		store32(&hash0[64], 0);
		store32(&hash0[68], (uint_least32_t)i);
#ifdef USING_LITTLE_ENDIAN
		argon2_blake2b_exthash(&memory[i * lanelen + 0], 1024, hash0, 72);
#else
		argon2_blake2b_exthash(block, 1024, hash0, 72);
		load_block(&memory[i * lanelen + 0], block);
#endif

		store32(&hash0[64], 1);
#ifdef USING_LITTLE_ENDIAN
		argon2_blake2b_exthash(&memory[i * lanelen + 1], 1024, hash0, 72);
#else
		argon2_blake2b_exthash(block, 1024, hash0, 72);
		load_block(&memory[i * lanelen + 1], block);
#endif
	}

	ERASE_ARRAY(hash0);

	if (ctx->init_thread_pool(params->lanes, &nthreads, ctx))
		goto fail;
	if (nthreads == 1) {
		nthreads = 0;
		if (ctx->destroy_thread_pool(ctx))
			goto fail;
	}

	if (!nthreads) {
		for (p = 0; p < params->t_cost; p++) {
			if (sbox)
				generate_sbox(sbox, memory);
			for (s = 0; s < 4; s++) {
				for (i = 0; i < params->lanes; i++) {
					fill_segment(memory, sbox, params, seglen, lanelen, blocks,
					             (uint_least32_t)p, (uint_least32_t)i, (uint_least32_t)s);
				}
			}
		}

	} else {
		tparams = ctx->allocate(nthreads, sizeof(*tparams), ALIGNOF(struct threaded_fill_segments_params), ctx);
		if (!tparams) {
			ctx->destroy_thread_pool(ctx);
			goto fail;
		}
		for (i = 0; i < nthreads; i++) {
			tparams[i].memory = memory;
			tparams[i].sbox = sbox;
			tparams[i].params = params;
			tparams[i].seglen = seglen;
			tparams[i].lanelen = lanelen;
			tparams[i].blocks = blocks;
		}

		for (p = 0; p < params->t_cost; p++) {
			if (sbox)
				generate_sbox(sbox, memory);
			for (s = 0; s < 4; s++) {
				ti = tn = 0;
				for (i = 0; i < params->lanes; i++) {
					if (ti == tn) {
						tn = ctx->get_ready_threads(ts, ELEMSOF(ts), ctx);
						if (!tn)
							goto fail;
						ti = 0;
					}
					tparams[ts[ti]].pass = (uint_least32_t)p;
					tparams[ts[ti]].lane = (uint_least32_t)i;
					tparams[ts[ti]].slice = (uint_least32_t)s;
					if (ctx->run_thread(ts[ti], threaded_fill_segment, &tparams[ts[ti]], ctx))
						goto fail;
					ti++;
				}
				if (ctx->join_thread_pool(ctx))
					goto fail;
			}
		}

		if (ctx->destroy_thread_pool(ctx))
			goto fail;
		ctx->deallocate(tparams, ctx);
		tparams = NULL;
	}

	for (i = 1; i < params->lanes; i++)
		memxor(&memory[lanelen - 1], &memory[i * lanelen + lanelen - 1], sizeof(*memory));
#ifdef USING_LITTLE_ENDIAN
	argon2_blake2b_exthash(hash, params->hashlen, &memory[lanelen - 1], 1024);
#else
	store_block(block, &memory[lanelen - 1]);
	argon2_blake2b_exthash(hash, params->hashlen, block, 1024);
#endif
	bufsize = libar2_hash_buf_size(params);
	if (bufsize) /* should never be 0 as that would indicate the user provided a too small buffer */
		libar2_erase(&((char *)hash)[params->hashlen], bufsize - params->hashlen);

#ifndef USING_LITTLE_ENDIAN
	ERASE_ARRAY(block);
#endif
	if (sbox)
		ctx->deallocate(sbox, ctx);
	ctx->deallocate(memory, ctx);
	return 0;

fail:
	if (tparams)
		ctx->deallocate(tparams, ctx);
	if (sbox)
		ctx->deallocate(sbox, ctx);
	ctx->deallocate(memory, ctx);
	return -1;
}
