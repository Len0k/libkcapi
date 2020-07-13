/*
 * Copyright (C) 2017 - 2020, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <linux/random.h>
#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif

#include <kcapi.h>

#include "app-internal.h"

/* For efficiency reasons, this should be identical to algif_rng.c:MAXSIZE. */
#define KCAPI_RNG_BUFSIZE  128
/* Minimum seed is 256 bits. */
#define KCAPI_RNG_MINSEEDSIZE 32

static struct kcapi_handle *rng = NULL;
static unsigned int Verbosity = KCAPI_LOG_WARN;
static char *rng_name = NULL;
static bool hexout = false;

#if !defined(HAVE_GETRANDOM) && !defined(__NR_getrandom)
static int random_fd = -1;
static int open_random(void)
{
	random_fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
	if (0 > random_fd)
		return random_fd;

	return 0;
}

static void close_random(void)
{
	close(random_fd);
}
#endif

static int get_random(uint8_t *buf, uint32_t buflen)
{
	ssize_t ret;

	if (buflen > INT_MAX)
		return 1;

#if (!defined(HAVE_GETRANDOM) && !defined(__NR_getrandom))
	ret = open_random();
	if (ret)
		return ret;
#endif

	do {
#ifdef HAVE_GETRANDOM
		ret = getrandom(buf, buflen, 0);
		dolog(KCAPI_LOG_DEBUG,
		      "Accessed getrandom system call for %u bytes", buflen);
#elif defined __NR_getrandom
		ret = syscall(__NR_getrandom, buf, buflen, 0);
		dolog(KCAPI_LOG_DEBUG,
		      "Accessed getrandom system call for %u bytes", buflen);
#else
		ret = read(random_fd, buf, buflen);
		dolog(KCAPI_LOG_DEBUG,
		      "Accessed /dev/urandom for %u bytes", buflen);
#endif
		if (0 < ret) {
			buflen -= ret;
			buf += ret;
		}
	} while ((0 < ret || EINTR == errno || ERESTART == errno)
		 && buflen > 0);

#if (!defined(HAVE_GETRANDOM) && !defined(__NR_getrandom))
	close_random();
#endif

	if (buflen == 0)
		return 0;
	return 1;
}

static void usage(void)
{
	char version[30];
	uint32_t ver = kcapi_version();

	memset(version, 0, sizeof(version));
	kcapi_versionstring(version, sizeof(version));

	fprintf(stderr, "\nKernel Crypto API Random Number Gatherer\n");
	fprintf(stderr, "\nKernel Crypto API interface library version: %s\n", version);
	fprintf(stderr, "Reported numeric version number %u\n\n", ver);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-b --bytes <BYTES>\tNumber of bytes to generate (required option)\n");
	fprintf(stderr, "\t-n --name <RNGNAME>\tDRNG name as advertised in /proc/crypto\n");
	fprintf(stderr, "\t\t\t\t(stdrng is default)\n");
	fprintf(stderr, "\t   --hex\t\tThe random number is returned in hexadecimal\n");
	fprintf(stderr, "\t\t\t\tnotation\n");
	fprintf(stderr, "\t-h --help\t\tThis help information\n");
	fprintf(stderr, "\t   --version\t\tPrint version\n");
	fprintf(stderr, "\t-v --verbose\t\tVerbose logging, multiple options increase\n");
	fprintf(stderr, "\t\t\t\tverbosity\n");
	fprintf(stderr, "\nData provided at stdin is used to seed the DRNG\n");

	exit(1);
}

static int parse_opts(int argc, char *argv[], unsigned long *outlen)
{
	int c = 0;
	char version[30];
	unsigned long bytes = 0;

	while (1) {
		int opt_index = 0;
		static struct option opts[] = {
			{"verbose",	no_argument,		0, 'v'},
			{"quiet",	no_argument,		0, 'q'},
			{"help",	no_argument,		0, 'h'},
			{"version",	no_argument,		0, 0},
			{"bytes",	required_argument,	0, 'b'},
			{"name",	required_argument,	0, 'n'},
			{"hex",		no_argument,		0, 0},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "vqhb:n:", opts, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				Verbosity++;
				break;
			case 1:
				Verbosity = KCAPI_LOG_NONE;
				break;
			case 2:
				usage();
				break;
			case 3:
				memset(version, 0, sizeof(version));
				kcapi_versionstring(version, sizeof(version));
				fprintf(stderr, "Version %s\n", version);
				exit(0);
				break;
			case 4:
				bytes = strtoul(optarg, NULL, 10);
				if (bytes == ULONG_MAX) {
					usage();
					return -EINVAL;
				}
				break;
			case 5:
				rng_name = optarg;
				break;
			case 6:
				hexout = true;
				break;
			default:
				usage();
			}
			break;
		case 'v':
			Verbosity++;
			break;
		case 'q':
			Verbosity = KCAPI_LOG_NONE;
			break;
		case 'h':
			usage();
			break;
		case 'b':
			bytes = strtoul(optarg, NULL, 10);
			if (bytes == ULONG_MAX) {
				usage();
				return -EINVAL;
			}
			break;
		case 'n':
			rng_name = optarg;
			break;
		default:
			usage();
		}
	}

	if (!bytes)
		usage();

	*outlen = bytes;
	return 0;
}

int test_cavp()
{
	int ret;
	const int num_bytes = 64;
	uint8_t buf[KCAPI_RNG_BUFSIZE] __aligned(KCAPI_APP_ALIGN);
	/*
	 * EntropyInput = ddbf2127c6745095c9476d1b346cf11f78ad7f2c8108e240b0f2c2c37f85fc2f
		Nonce = 00478ba2fbad6f4e41e6604a7fa393a7
		PersonalizationString = b20598b551f3145b9b4adac17ff0c3a357ed9d055e650442d752ab47b7a65295
		AdditionalInput = 4882cff5e230e0b9f7ce67b891dd81972c59a4c0f41b7aaa555dd6797680aa48
		AdditionalInput = 4c8ddc6c0f85fdc0cb1db4937073d2c8e8846389e4738e5badfa8204f1751792
		ReturnedBits = ab72fa9918018f8b85fab3a5d83cf9c7e89699522c9c615efff416387f73dc7c940d92b7d7e5ea9653fc5c67c3d4a8d15d2833f5b46fea6baf5816b4c19c6aa9
	 */
	uint8_t entropy_input[] = "\xdd\xbf\x21\x27\xc6\x74\x50\x95\xc9\x47\x6d\x1b\x34\x6c\xf1\x1f\x78\xad\x7f\x2c\x81\x08\xe2\x40\xb0\xf2\xc2\xc3\x7f\x85\xfc\x2f" "\x00\x47\x8b\xa2\xfb\xad\x6f\x4e\x41\xe6\x60\x4a\x7f\xa3\x93\xa7";
	uint8_t personalization_string[] = "\xb2\x05\x98\xb5\x51\xf3\x14\x5b\x9b\x4a\xda\xc1\x7f\xf0\xc3\xa3\x57\xed\x9d\x05\x5e\x65\x04\x42\xd7\x52\xab\x47\xb7\xa6\x52\x95";  // a.k.a. seed
	uint8_t additional_a[] = "\x48\x82\xcf\xf5\xe2\x30\xe0\xb9\xf7\xce\x67\xb8\x91\xdd\x81\x97\x2c\x59\xa4\xc0\xf4\x1b\x7a\xaa\x55\x5d\xd6\x79\x76\x80\xaa\x48";
	uint8_t additional_b[] = "\x4c\x8d\xdc\x6c\x0f\x85\xfd\xc0\xcb\x1d\xb4\x93\x70\x73\xd2\xc8\xe8\x84\x63\x89\xe4\x73\x8e\x5b\xad\xfa\x82\x04\xf1\x75\x17\x92";
	ret = kcapi_rng_init(&rng, "drbg_nopr_ctr_aes256", 0);
	if (ret)
		return ret;
	kcapi_rng_set_entropy(rng, entropy_input, sizeof(entropy_input) - 1);

	ret = kcapi_rng_seed(rng, personalization_string, sizeof(personalization_string) - 1);
	if (ret)
		goto out;
	dolog(KCAPI_LOG_DEBUG, "Seeding the DRNG with %u bytes of data",
	      sizeof(personalization_string) - 1);

	// calling generate twice is not the same as calling it with 2*num_bytes
	ret = kcapi_rng_send_addtl(rng, additional_a, sizeof(additional_a) - 1);
	if (ret < 0)
		goto out;
	ret = kcapi_rng_generate(rng, buf, num_bytes);
	if (ret < 0)
		goto out;
	ret = kcapi_rng_send_addtl(rng, additional_b, sizeof(additional_b) - 1);
	if (ret < 0)
		goto out;
	ret = kcapi_rng_generate(rng, buf, num_bytes);
	if (ret < 0)
		goto out;
	char hexbuf[2 * KCAPI_RNG_BUFSIZE];
	bin2hex(buf, ret, hexbuf, sizeof(hexbuf), 0);
	fwrite(hexbuf, 2 * ret, 1, stdout);
	ret = 0;

out:
	if (rng)
		kcapi_rng_destroy(rng);

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;
	uint8_t buf[KCAPI_RNG_BUFSIZE] __aligned(KCAPI_APP_ALIGN);
	uint8_t *seedbuf = buf;
	uint32_t seedsize = 0;
	unsigned long outlen;

	ret = parse_opts(argc, argv, &outlen);
	if (ret)
		return ret;

	set_verbosity("kcapi-rng", Verbosity);

	if (rng_name) {
		if (!strncmp(rng_name, "cavp", 4))
			return test_cavp();
		ret = kcapi_rng_init(&rng, rng_name, 0);
	} else {
		ret = kcapi_rng_init(&rng, "stdrng", 0);
	}
	if (ret)
		return ret;

	seedsize = kcapi_rng_seedsize(rng);
	if (seedsize) {
		/*
		 * Only reseed, if there is a seedsize defined. For example,
		 * the DRBG has a seedsize of 0 because it seeds itself from
		 * known good noise sources.
		 */
		if (seedsize < KCAPI_RNG_MINSEEDSIZE)
			seedsize = KCAPI_RNG_MINSEEDSIZE;

		/*
		 * Only allocate a new buffer if our buffer is
		 * insufficiently large.
		 */
		if (seedsize > KCAPI_RNG_BUFSIZE) {
			seedbuf = calloc(1, seedsize);
			if (!seedbuf) {
				ret = -ENOMEM;
				goto out;
			}
		}

		ret = get_random(seedbuf, seedsize);
		if (ret)
			goto out;
	}

	/*
	 * Invoke seeding even if seedsize is 0 -- this also triggers any
	 * internal seeding operation like in the DRBG.
	 */
	ret = kcapi_rng_seed(rng, seedbuf, seedsize);
	if (ret)
		goto out;
	dolog(KCAPI_LOG_DEBUG, "Seeding the DRNG with %u bytes of data",
	      seedsize);

	if (!isatty(0) && (errno == EINVAL || errno == ENOTTY)) {
		while (fgets((char *)seedbuf, seedsize, stdin)) {
			ret = kcapi_rng_seed(rng, seedbuf, seedsize);
			if (ret)
				dolog(KCAPI_LOG_WARN,
				      "User-provided seed of %lu bytes not accepted by DRNG (error: %d)",
				      (unsigned long)sizeof(buf), ret);
			else
				dolog(KCAPI_LOG_DEBUG,
				      "User-provided seed of %u bytes",
				      seedsize);
		}
	}

	while (outlen) {
		uint32_t todo = (outlen < KCAPI_RNG_BUFSIZE) ?
					outlen : KCAPI_RNG_BUFSIZE;

		ret = kcapi_rng_generate(rng, buf, todo);
		if (ret < 0)
			goto out;

		if ((uint32_t)ret == 0) {
			ret = -EFAULT;
			goto out;
		}

		if (hexout) {
			char hexbuf[2 * KCAPI_RNG_BUFSIZE];

			bin2hex(buf, ret, hexbuf, sizeof(hexbuf), 0);
			fwrite(hexbuf, 2 * ret, 1, stdout);
		} else {
			fwrite(buf, ret, 1, stdout);
		}

		outlen -= ret;
	}

	ret = 0;

out:
	if (rng)
		kcapi_rng_destroy(rng);
	kcapi_memset_secure(buf, 0, sizeof(buf));

	/* Free seedbuf if it was allocated. */
	if (seedbuf && (seedbuf != buf)) {
		kcapi_memset_secure(seedbuf, 0, seedsize);
		free(seedbuf);
	}

	return ret;
}
