/* See LICENSE file for copyright and license details. */
#ifndef LIBAR2_H
#define LIBAR2_H

#include <stddef.h>
#include <stdint.h>

/* for internal use { */

#if defined(UINT_LEAST32_C)
# define LIBAR2_UINT_LEAST32_C__(V) UINT_LEAST32_C(V)
#elif defined(UINT32_C)
# define LIBAR2_UINT_LEAST32_C__(V) UINT32_C(V)
#else
# define LIBAR2_UINT_LEAST32_C__(V) V##UL
#endif

#define LIBAR2_MIN_T_COST LIBAR2_UINT_LEAST32_C__(1)
#define LIBAR2_MAX_T_COST LIBAR2_UINT_LEAST32_C__(0xFFFFffff)
#define LIBAR2_MIN_M_COST LIBAR2_UINT_LEAST32_C__(8)
#define LIBAR2_MAX_M_COST ((uint_least32_t)((SIZE_MAX >> 11) & LIBAR2_UINT_LEAST32_C__(0xFFFFffff)))
#define LIBAR2_MIN_LANES LIBAR2_UINT_LEAST32_C__(1)
#define LIBAR2_MAX_LANES LIBAR2_UINT_LEAST32_C__(0xFFFFff)
#define LIBAR2_MIN_SALTLEN ((size_t)LIBAR2_UINT_LEAST32_C__(8))
#define LIBAR2_MAX_SALTLEN ((size_t)LIBAR2_UINT_LEAST32_C__(0xFFFFffff))
#define LIBAR2_MAX_KEYLEN ((size_t)LIBAR2_UINT_LEAST32_C__(0xFFFFffff))
#define LIBAR2_MAX_ADLEN ((size_t)LIBAR2_UINT_LEAST32_C__(0xFFFFffff))
#define LIBAR2_MIN_HASHLEN ((size_t)LIBAR2_UINT_LEAST32_C__(4))
#define LIBAR2_MAX_HASHLEN ((size_t)LIBAR2_UINT_LEAST32_C__(0xFFFFffff))
#define LIBAR2_IS_TYPE_OK(T) ((T) == LIBAR2_ARGON2D || (T) == LIBAR2_ARGON2I || (T) == LIBAR2_ARGON2ID || (T) == LIBAR2_ARGON2DS)
#define LIBAR2_IS_VERSION_OK(V) ((V) == LIBAR2_ARGON2_VERSION_10 || (V) == LIBAR2_ARGON2_VERSION_13)

/* } */

/**
 * List all parameter errors
 * 
 * @param  X  Macro to expand for each error
 * @param  P  A `const struct libar2_argon2_parameters *` to inspect
 */
#define LIBAR2_LIST_PARAMETER_ERRORS(X, P)\
	X(LIBAR2_T_COST_TOO_SMALL, "time-cost parameter is too small", (P)->t_cost < LIBAR2_MIN_T_COST)\
	X(LIBAR2_T_COST_TOO_LARGE, "time-cost parameter is too large", (P)->t_cost > LIBAR2_MAX_T_COST)\
	X(LIBAR2_M_COST_TOO_SMALL, "memory-cost parameter is too small", (P)->m_cost < LIBAR2_MIN_M_COST)\
	X(LIBAR2_M_COST_TOO_LARGE, "memory-cost parameter is too large", (P)->m_cost > LIBAR2_MAX_M_COST)\
	X(LIBAR2_TOO_FEW_LANES, "lane-count parameter is too small", (P)->lanes < LIBAR2_MIN_LANES)\
	X(LIBAR2_TOO_MANY_LANES, "lane-count parameter is too large", (P)->lanes > LIBAR2_MAX_LANES)\
	X(LIBAR2_SALT_TOO_SMALL, "salt parameter is too small", (P)->saltlen < LIBAR2_MIN_SALTLEN)\
	X(LIBAR2_SALT_TOO_LARGE, "salt parameter is too large", (P)->saltlen > LIBAR2_MAX_SALTLEN)\
	X(LIBAR2_KEY_TOO_LARGE, "secret parameter is too large", (P)->keylen > LIBAR2_MAX_KEYLEN)\
	X(LIBAR2_AD_TOO_LARGE, "associated data parameter is too large", (P)->adlen > LIBAR2_MAX_ADLEN)\
	X(LIBAR2_HASH_TOO_SMALL, "tag length parameter is too small", (P)->hashlen < LIBAR2_MIN_HASHLEN)\
	X(LIBAR2_HASH_TOO_LARGE, "tag length parameter is too large", (P)->hashlen > LIBAR2_MAX_HASHLEN)\
	X(LIBAR2_INVALID_TYPE, "type parameter is invalid", !LIBAR2_IS_TYPE_OK((P)->type))\
	X(LIBAR2_INVALID_VERSION, "version parameter is invalid", !LIBAR2_IS_VERSION_OK((P)->version))

/**
 * Parameter errors
 */
enum libar2_parameter_error {

	/**
	 * No error
	 */
	LIBAR2_OK = 0

#define LIBAR2_X__(ENUM, ERRMESG, CONDITION) ,ENUM
	LIBAR2_LIST_PARAMETER_ERRORS(LIBAR2_X__,)
#undef LIBAR2_X__
};

/**
 * String case
 */
enum libar2_casing {

	/**
	 * Lower case, e.g. "argon2i"
	 */
	LIBAR2_LOWER_CASE = 0,

	/**
	 * Title case, e.g. "Argon2i"
	 */
	LIBAR2_TITLE_CASE = 1,

	/**
	 * Upper case, e.g. "ARGON2I"
	 */
	LIBAR2_UPPER_CASE = 2
};

/**
 * Argon2 primitive types
 */
enum libar2_argon2_type {

	/**
	 * Secret-dependent hashing
	 * 
	 * Only for side-channel-free environment!
	 */
	LIBAR2_ARGON2D = 0,

	/**
	 * Secret-independent hashing
	 * 
	 * Good for side-channels but worse with respect
	 * to trade of attacks if only one pass is used
	 */
	LIBAR2_ARGON2I = 1,

	/**
	 * Hybrid construction
	 * 
	 * OK against side channels and better with
	 * respect to tradeoff attacks
	 */
	LIBAR2_ARGON2ID = 2,

	/* There is no type with value 3 */

	/**
	 * Substition box (S-box)-hardened
	 */
	LIBAR2_ARGON2DS = 4
};

/**
 * Argon2 versions
 */
enum libar2_argon2_version {

	/**
	 * Argon2 version 1.0 ("10")
	 */
	LIBAR2_ARGON2_VERSION_10 = 0x10,

	/**
	 * Argon2 version 1.3 ("13")
	 */
	LIBAR2_ARGON2_VERSION_13 = 0x13
};

/**
 * Argon2 hashing parameters
 */
struct libar2_argon2_parameters {

	/**
	 * Primitive type
	 */
	enum libar2_argon2_type type;

	/**
	 * Version number
	 * 
	 * `libar2_latest_argon2_version` is recommended
	 */
	enum libar2_argon2_version version;

	/**
	 * Number of passes
	 * 
	 * At least 1, at most 2³²−1
	 */
	uint_least32_t t_cost;

	/**
	 * Amount of required memory, in kilobytes
	 * 
	 * At least 8, at most MAX(2³²−1, address-space » 11)
	 */
	uint_least32_t m_cost;

	/**
	 * Number of lanes
	 * 
	 * At least 1, at most 2²⁴−1
	 */
	uint_least32_t lanes;

	/**
	 * Salt, binary
	 * 
	 * Only modified if `.autoerase_salt` in
	 * `struct libar2_context` is non-zero
	 */
	unsigned char *salt;

	/**
	 * The length (bytes) of the salt
	 * 
	 * At least 8, at most 2³²−1
	 */
	size_t saltlen;

	/**
	 * Secret (pepper), binary [optional]
	 * 
	 * Only modified if `.autoerase_secret` in
	 * `struct libar2_context` is non-zero
	 */
	unsigned char *key;

	/**
	 * The length (bytes) of the secret
	 * 
	 * At least 0, at most 2³²−1
	 */
	size_t keylen;

	/**
	 * Arbitrary extra associated data, binary [optional]
	 * 
	 * Only modified if `.autoerase_associated_data`
	 * in `struct libar2_context` is non-zero
	 */
	unsigned char *ad;

	/**
	 * The length (bytes) of the associated
	 * 
	 * At least 0, at most 2³²−1
	 */
	size_t adlen;

	/**
	 * The length (bytes) of the output hash
	 * 
	 * At least 4, at most 2³²−1
	 */
	size_t hashlen;
};

/**
 * Library settings
 */
struct libar2_context {

	/**
	 * User-defined data
	 */
	void *user_data;

	/**
	 * Whether the message shall be erased
	 * immediately when it's no longer need
	 * 
	 * Assumming the message is a password,
	 * you would normally set this to non-zero
	 * (properly 1), unless the password is in
	 * read-only memory for will be needed for
	 * rehashing with a stronger algorithm or
	 * new parameters
	 */
	unsigned char autoerase_message;

	/**
	 * Whether the secret shall be erased
	 * immediately when it's no longer need
	 */
	unsigned char autoerase_secret;

	/**
	 * Whether the salt shall be erased
	 * immediately when it's no longer need
	 */
	unsigned char autoerase_salt;

	/**
	 * Whether the associated data shall be
	 * erased immediately when it's no longer
	 * need
	 */
	unsigned char autoerase_associated_data;

	/**
	 * Memory allocation function
	 * 
	 * It is safe to assume that `.allocate` and
	 * `.deallocate` will be called in stack order
	 * and never in threads run using `.run_thread`
	 * 
	 * Example implementation:
	 * 
	 *     static void *
	 *     allocate(size_t num, size_t size, size_t alignment, struct libar2_context *ctx)
	 *     {
	 *             void *ptr;
	 *             int err;
	 *             (void) ctx;
	 *             if (num > SIZE_MAX / size) {
	 *                     errno = ENOMEM;
	 *                     return NULL;
	 *             }
	 *             if (alignment < sizeof(void *))
	 *                     alignment = sizeof(void *);
	 *             err = posix_memalign(&ptr, alignment, num * size);
	 *             if (err) {
	 *                     errno = err;
	 *                     return NULL;
	 *             } else {
	 *                     return ptr;
	 *             }
	 *     }
	 * 
	 * @param   num        The number of elements to allocate, never 0
	 * @param   size       The size of each element, never 0
	 * @param   alignment  Requires memory alignment, never 0
	 * @param   ctx        The structure containing the callback
	 * @return             Pointer to the allocated memory, `NULL` on failure
	 */
	void *(*allocate)(size_t num, size_t size, size_t alignment, struct libar2_context *ctx);

	/**
	 * Memory deallocation function
	 * 
	 * The application may which to earse the memory before
	 * deallocating it; this is not done by the library.
	 * This can be done using `libar2_earse`;
	 * 
	 * Example implementation:
	 * 
	 *     static void
	 *     deallocate(void *ptr, struct libar2_context *ctx)
	 *     {
	 *             (void) ctx;
	 *             free(ptr);
	 *     }
	 * 
	 * @param  ptr  The pointer to the memory to deallocate,
	 *              always a pointer returned by `.allocate`
	 * @param  ctx  The structure containing the callback
	 */
	void (*deallocate)(void *ptr, struct libar2_context *ctx);

	/**
	 * Initialise the thread pool
	 * 
	 * If thread support is desired, but the application do not
	 * want to keep track of the threads using a thread pool,
	 * this function must store `desired` in `*createdp`. The
	 * application must also, in this case, make sure that
	 * `.join_thread_pool` returns after all started threads
	 * have stopped, and `.get_ready_threads` store unique
	 * indices within the range [0, `desired`) (start with
	 * `i = 0` and each time an index is stored, calculate it
	 * with `i++ % desired`). Alternatively, and more preferably,
	 * this scheme can be used, but adapted to limit the number
	 * of concurrent threads, keeping track of the number of
	 * running threads, and not let `.get_ready_threads` return
	 * before this number is small enough; `*createdp` must however
	 * still set to `desired` so that to threads are not running
	 * concurrently with the same memory segment as the provided
	 * argument for the function to run, as this could be a source
	 * of memory corruption. It is however recommended to implement
	 * proper thread pooling as the library will call `.run_thread`
	 * `4 * params->t_cost * params->lanes` times where `params`
	 * is the used `struct libar2_argon2_parameters *`.
	 * 
	 * @param   desired   The number of threads that, at a maximum,
	 *                    will be used by the library, from the
	 *                    thread pool
	 * @param   createdp  Output parameter for the number of threads
	 *                    allocated, 0 if threading is disabled,
	 *                    which is preferable if `desired` is 1
	 * @param   ctx       The structure containing the callback
	 * @return            0 on success, -1 on failure (the calling
	 *                    function will exit indicating error and keep
	 *                    the value of `errno` set by this function)
	 */
	int (*init_thread_pool)(size_t desired, size_t *createdp, struct libar2_context *ctx);

	/**
	 * Wait until at least one thread in the pool is ready
	 * (may be immediately), and get some of their indices
	 * 
	 * @param   indices  Output array for the indices of the ready threads
	 * @param   n        The maximum number of thread indices to store in `indices`;
	 *                   this number may exceed the number of created, or even
	 *                   requested, threads, or the number of threads the function
	 *                   will attempt to use
	 * @param   ctx      The structure containing the callback
	 * @return           The number of ready threads (non-zero, but may exceed `n`);
	 *                   0 on failure (the calling function will exit indicating
	 *                   error and keep the value of `errno` set by this function)
	 */
	size_t (*get_ready_threads)(size_t *indices, size_t n, struct libar2_context *ctx);

	/**
	 * Run a function in a thread
	 * 
	 * The requested thread will be guaranteed by
	 * `.get_ready_threads` to be ready
	 * 
	 * @param   index     The index of the thread to use
	 * @param   function  The function to run
	 * @param   data      Argument to provide to `function`
	 * @param   ctx       The structure containing the callback
	 * @return            0 on success, -1 on failure (the calling
	 *                    function will exit indicating error and keep
	 *                    the value of `errno` set by this function)
	 */
	int (*run_thread)(size_t index, void (*function)(void *data), void *data, struct libar2_context *ctx);

	/**
	 * Wait until all threads in the thread pool are resting
	 * 
	 * @param   ctx  The structure containing the callback
	 * @return       0 on success, -1 on failure (the calling
	 *               function will exit indicating error and keep
	 *               the value of `errno` set by this function)
	 */
	int (*join_thread_pool)(struct libar2_context *ctx);

	/**
	 * Destroy the thread pool, and all threads in it
	 * (each of the will be resting)
	 * 
	 * Will be called iff `.init_thread_pool` was called
	 * successfully and returned a non-zero thread
	 * count, except, not if `.join_thread_pool` or
	 * `.get_ready_threads` failed
	 * 
	 * @param   ctx  The structure containing the callback
	 * @return       0 on success, -1 on failure (the calling
	 *               function will exit indicating error and keep
	 *               the value of `errno` set by this function)
	 */
	int (*destroy_thread_pool)(struct libar2_context *ctx);
};


/**
 * The latest versions of Argon2 that is supported
 */
extern enum libar2_argon2_version libar2_latest_argon2_version;


/**
 * Convert an Argon2 primitive type value to a string
 * 
 * @param   type    The primitive type
 * @param   casing  The case that the string shalll use
 * @return          String representing the type, `NULL` (with `errno`
 *                  set to EINVAL) if either argument is invalid
 */
const char *libar2_type_to_string(enum libar2_argon2_type type, enum libar2_casing casing);

/**
 * Convert a string to an Argon2 primitive type value
 * 
 * @param   str    String representing the primitive type
 * @param   typep  Output parameter for the primitive type
 * @return         0 on success, -1 (with `errno` set to EINVAL) if `str` is invalid
 */
int libar2_string_to_type(const char *str, enum libar2_argon2_type *typep);

/**
 * Convert an Argon2 version number value to a string,
 * will be returned without a dot
 * 
 * @param   version  The version number value
 * @return           String representing the version, `NULL` (with
 *                   `errno` set to EINVAL) if `version` is invalid
 */
const char *libar2_version_to_string(enum libar2_argon2_version version);

/**
 * Convert an Argon2 version number value to a string,
 * will be returned with a dot
 * 
 * @param   version  The version number value
 * @return           String representing the version, `NULL` (with
 *                   `errno` set to EINVAL) if `version` is invalid
 */
const char *libar2_version_to_string_proper(enum libar2_argon2_version version);

/**
 * Convert a string to an Argon2 version number value
 * 
 * @param   str       String representing the version
 * @param   versionp  Output parameter for the version number value
 * @return            0 on success, -1 (with `errno` set to EINVAL) if `str` is invalid
 */
int libar2_string_to_version(const char *str, enum libar2_argon2_version *versionp);

/**
 * Encode hashing parameters
 * 
 * Secret, associated data, and tag length (`params->hashlen`)
 * will not be included in the output
 * 
 * To encode a string with both the parameters and the
 * hash, simply append the output of `libar2_encode_base64`
 * over the hash onto the output of this function
 * 
 * @param   buf     Output buffer, or `NULL`
 * @param   params  Hashing parameters
 * @return          The number of bytes required for `buf`,
 *                  including the NUL byte added to the end
 */
size_t libar2_encode_params(char *buf, const struct libar2_argon2_parameters *params);

/**
 * Encode data with base64 encoding, which is what
 * Argon2 uses, rather than B64 which is what crypt(3)
 * uses; however this version of base64 is not padded
 * to a length divible by 4
 * 
 * @param   buf   Output buffer, or `NULL`
 * @param   data  The data to encode
 * @param   len   The number of bytes in `data`
 * @return        The number of bytes required for `buf`,
 *                including the NUL byte added to the end
 */
size_t libar2_encode_base64(char *buf, const void *data, size_t len);

/**
 * Decode hashing parameters
 * 
 * Secret and associated data will be set to zero-length
 * 
 * It is recommended that application stores that default
 * parameters encoded with `libar2_encode_params` using
 * a hash of only null bytes. When the allocation decodes
 * this string before generating the hash for a new password,
 * it would refill the salt buffer with random bytes. The
 * salt buffer will be allocated by this function.
 * 
 * The tag length (`params->hashlen`) will calculated from
 * that hash at the end of `str`, however, the encoded length
 * of the hash will not be included in the function's return
 * value
 * 
 * @param   str     Hashing parameter string
 * @param   params  Output parameter for the hashing parameters
 * @param   bufp    Output parameter for buffer containing variable
 *                  length data in `params`; will be allocated
 *                  using `ctx->allocate`
 * @param   ctx     `.allocate` and `.deallocate` must be set
 * @return          The number of bytes read, 0 if `str` is improperly
 *                  formatted (EINVAL), contain an unrecognised primitive
 *                  type (EINVAL), or contained a value that is too large
 *                  to be stored (ERANGE) (otherwise invalid parameters
 *                  are not checked); if a callback from `ctx` fails, 0
 *                  is returned with `errno` set to the value set by the
 *                  callback; if non-zero is returned, and `str` contains
 *                  a hash, and not just parameters, `&str[return]` will
 *                  point to the hash
 */
size_t libar2_decode_params(const char *str, struct libar2_argon2_parameters *params, char **bufp, struct libar2_context *ctx);

/**
 * Decode data encoded with base64 (padding with '=' is optional)
 * 
 * @param   str   The data to decode
 * @param   data  Output buffer for the decoded data, or `NULL`
 * @param   lenp  Output parameter for the length of the decoded data
 * @return        The number of bytes read
 */
size_t libar2_decode_base64(const char *str, void *data, size_t *lenp);

/**
 * Validate hashing parameters
 * 
 * @param   params   The hashing parameters
 * @param   errmsgp  Output parameter for the error message, or `null`
 * @return           The first detected error, or LIBAR2_OK (0) if none
 */
enum libar2_parameter_error libar2_validate_params(const struct libar2_argon2_parameters *params, const char **errmsgp);

/**
 * Securily earse memory
 * 
 * @param  mem   The memory to erase
 * @param  size  The number of bytes to erase
 */
void libar2_earse(volatile void *mem, size_t size);

/**
 * Hash a message
 * 
 * The recommended why of verify a password is to hash the
 * provided password with this function, convert the known
 * hash with `libar2_decode_base64` to binary (if it's not
 * already in binary), and let `h` be the result of this
 * function, `k` be the known password hash, and `n` be
 * `params->hashlen`, then the password is correct iff
 * `d`, as computed below, is 0:
 *  
 *      unsigned char d = 0;
 *      size_t i;
 *      for (i = 0; i < n; i++) {
 *          d |= h[i] ^ k[i];
 *      }
 * 
 * It is preferable this check is done by the process that
 * knowns the correct password hash, and that the tryed
 * password is hashed before it is sent to that process
 * 
 * Note that on failure, the function will not necessarily
 * have erased data configured in `ctx` to be automatically
 * erased
 * 
 * @param   hash    Binary hash ("tag") output buffer, shall
 *                  be at least `params->hashlen` bytes large
 * @param   msg     Message (password) to hash; only modified if
 *                  `ctx->autoerase_message` is non-zero
 * @param   msglen  The length of `msg`; at least 0, at most 2³²−1
 * @param   params  Hashing parameters
 * @param   ctx     Library settings
 * @return          0 on success, -1 on failure
 */
int libar2_hash(void *hash, void *msg, size_t msglen, struct libar2_argon2_parameters *params, struct libar2_context *ctx);

#endif
