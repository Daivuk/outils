#if defined(WIN32)
#include <Windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <dirent/dirent.h>
#elif defined(__linux__) || defined(__APPLE__)
#include <dirent.h>
#include <iostream>
#endif
#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>
#include "outils/outils.h"
#include "tinyfiledialogs/tinyfiledialogs.h"

static bool isCharacter(const char Character)
{
    return ((Character >= 'a' && Character <= 'z') || (Character >= 'A' && Character <= 'Z'));
    //Checks if a Character is a Valid A-Z, a-z Character, based on the ascii value
}

static bool isValidEmailAddress(const char * EmailAddress)
{
    if (!EmailAddress) // If cannot read the Email Address...
        return 0;
    if (!isCharacter(EmailAddress[0])) // If the First character is not A-Z, a-z
        return 0;
    int AtOffset = -1;
    int DotOffset = -1;
    size_t Length = strlen(EmailAddress); // Length = StringLength (strlen) of EmailAddress
    for (size_t i = 0; i < Length; i++)
    {
        if (EmailAddress[i] == '@') // If one of the characters is @, store it's position in AtOffset
            AtOffset = (int)i;
        else if (EmailAddress[i] == '.') // Same, but with the dot
            DotOffset = (int)i;
    }
    if (AtOffset == -1 || DotOffset == -1) // If cannot find a Dot or a @
        return 0;
    if (AtOffset > DotOffset) // If the @ is after the Dot
        return 0;
    return !(DotOffset >= ((int)Length - 1)); //Chech there is some other letters after the Dot
}


#ifndef __MD5_H__
#define __MD5_H__

/*
 * Size of a standard MD5 signature in bytes.  This definition is for
 * external programs only.  The MD5 routines themselves reference the
 * signature as 4 unsigned 32-bit integers.
 */
const unsigned int MD5_SIZE = (4 * sizeof(unsigned int));   /* 16 */
const unsigned int MD5_STRING_SIZE = 2 * MD5_SIZE + 1;      /* 33 */

 namespace md5 {
    /*
     * The MD5 algorithm works on blocks of characters of 64 bytes.  This
     * is an internal value only and is not necessary for external use.
     */
    const unsigned int BLOCK_SIZE = 64;

    class md5_t {
        public:
            /*
             * md5_t
             *
             * DESCRIPTION:
             *
             * Initialize structure containing state of MD5 computation. (RFC 1321,
             * 3.3: Step 3).  This is for progressive MD5 calculations only.  If
             * you have the complete string available, call it as below.
             * process should be called for each bunch of bytes and after the last
             * process call, finish should be called to get the signature.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * None.
             */
            md5_t();

            /*
             * md5_t
             *
             * DESCRIPTION:
             *
             * This function is used to calculate a MD5 signature for a buffer of
             * bytes.  If you only have part of a buffer that you want to process
             * then md5_t, process, and finish should be used.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * input - A buffer of bytes whose MD5 signature we are calculating.
             *
             * input_length - The length of the buffer.
             *
             * signature_ - A 16 byte buffer that will contain the MD5 signature.
             */
            md5_t(const void* input, const unsigned int input_length, void* signature_ = NULL);

            /*
             * process
             *
             * DESCRIPTION:
             *
             * This function is used to progressively calculate an MD5 signature some
             * number of bytes at a time.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * input - A buffer of bytes whose MD5 signature we are calculating.
             *
             * input_length - The length of the buffer.
             */
            void process(const void* input, const unsigned int input_length);

            /*
             * finish
             *
             * DESCRIPTION:
             *
             * Finish a progressing MD5 calculation and copy the resulting MD5
             * signature into the result buffer which should be 16 bytes
             * (MD5_SIZE).  After this call, the MD5 structure cannot be used
             * to calculate a new md5, it can only return its signature.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * signature_ - A 16 byte buffer that will contain the MD5 signature.
             */
            void finish(void* signature_ = NULL);

            /*
             * get_sig
             *
             * DESCRIPTION:
             *
             * Retrieves the previously calculated signature from the MD5 object.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * signature_ - A 16 byte buffer that will contain the MD5 signature.
             */
            void get_sig(void* signature_);

            /*
             * get_string
             *
             * DESCRIPTION:
             *
             * Retrieves the previously calculated signature from the MD5 object in
             * printable format.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * str_ - a string of characters which should be at least 33 bytes long
             * (2 characters per MD5 byte and 1 for the \0).
             */
            void get_string(void* str_);

        private:
            /* internal functions */
            void initialise();
            void process_block(const unsigned char*);
            void get_result(void*);

            unsigned int A;                             /* accumulator 1 */
            unsigned int B;                             /* accumulator 2 */
            unsigned int C;                             /* accumulator 3 */
            unsigned int D;                             /* accumulator 4 */

            unsigned int message_length[2];             /* length of data */
            unsigned int stored_size;                   /* length of stored bytes */
            unsigned char stored[md5::BLOCK_SIZE * 2];  /* stored bytes */

            bool finished;                              /* object state */

            char signature[MD5_SIZE];                   /* stored signature */
            char str[MD5_STRING_SIZE];                  /* stored plain text hash */
    };

    /*
     * sig_to_string
     *
     * DESCRIPTION:
     *
     * Convert a MD5 signature in a 16 byte buffer into a hexadecimal string
     * representation.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature - a 16 byte buffer that contains the MD5 signature.
     *
     * str - a string of characters which should be at least 33 bytes long (2
     * characters per MD5 byte and 1 for the \0).
     *
     * str_len - the length of the string.
     */
    extern void sig_to_string(const void* signature, char* str, const int str_len);

    /*
     * sig_from_string
     *
     * DESCRIPTION:
     *
     * Convert a MD5 signature from a hexadecimal string representation into
     * a 16 byte buffer.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature - A 16 byte buffer that will contain the MD5 signature.
     *
     * str - A string of charactes which _must_ be at least 32 bytes long (2
     * characters per MD5 byte).
     */
    extern void sig_from_string(void* signature, const char* str);
} // namespace md5

#endif /* ! __MD5_H__ */

/*
 * Local defines for the md5 functions.
 *
 * $Id: md5_loc.h,v 1.5 2010-05-07 13:58:18 gray Exp $
 */

#ifndef __MD5_LOC_H__
#define __MD5_LOC_H__

/*
 * We don't include "conf.h" here because it gets included before this file in md5.cpp so the defines
 * are correctly determing before they are checked.
 */
 #if MD5_DEBUG
    #include <iostream>
#endif // MD5_DEBUG

/// For now we are assuming everything is in little endian byte-order

namespace md5 {
    /*
     * T denotes the integer part of the i-th element of the function:
     * T[i] = 4294967296 * abs(sin(i)), where i is in radians.
     */
    const unsigned int T[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    /*
     * Constants for the MD5 Transform routine as defined in RFC 1321
     */
    const unsigned int S1[4] = {7, 12, 17, 22};
    const unsigned int S2[4] = {5, 9,  14, 20};
    const unsigned int S3[4] = {4, 11, 16, 23};
    const unsigned int S4[4] = {6, 10, 15, 21};

    /*
     * Function to perform the cyclic left rotation of blocks of data
     */
    inline unsigned int cyclic_left_rotate(unsigned int data, unsigned int shift_bits) {
        return (data << shift_bits) | (data >> (32 - shift_bits));
    }

    inline unsigned int F(unsigned int x, unsigned int y, unsigned int z) {return (x & y) | (~x & z);};
    inline unsigned int G(unsigned int x, unsigned int y, unsigned int z) {return (x & z) | (y & ~z);};
    inline unsigned int H(unsigned int x, unsigned int y, unsigned int z) {return x ^ y ^ z;};
    inline unsigned int I(unsigned int x, unsigned int y, unsigned int z) {return y ^ (x | ~z);};

    inline void FF(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Xk, unsigned int s, unsigned int i) {
        #if MD5_DEBUG
            std::cout << "\nA: " << a << "\nB: " << b << "\nC: " << c << "\nD: " << d << "\nX[" << i << "]: " << Xk << "\ns: " << S1[s] << "\nT: " << T[i] << "\n";
        #endif

        a += F(b,c,d) + Xk + T[i];
        a = cyclic_left_rotate(a, S1[s]);
        a += b;

        #if MD5_DEBUG
            std::cout << "A = " << a << "\n";
        #endif
    };

    inline void GG(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Xk, unsigned int s, unsigned int i) {
        #if MD5_DEBUG
            std::cout << "\nA: " << a << "\nB: " << b << "\nC: " << c << "\nD: " << d << "\nX[" << i - 16 << "]: " << Xk << "\ns: " << S2[s] << "\nT: " << T[i] << "\n";
        #endif // MD5_DEBUG

        a += G(b,c,d) + Xk + T[i];
        a = cyclic_left_rotate(a, S2[s]);
        a += b;

        #if MD5_DEBUG
            std::cout << "A = " << a << "\n";
        #endif // MD5_DEBUG
    };

    inline void HH(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Xk, unsigned int s, unsigned int i) {
        #if MD5_DEBUG
            std::cout << "\nA: " << a << "\nB: " << b << "\nC: " << c << "\nD: " << d << "\nX[" << i - 32 << "]: " << Xk << "\ns: " << S3[s] << "\nT: " << T[i] << "\n";
        #endif // MD5_DEBUG

        a += H(b,c,d) + Xk + T[i];
        a = cyclic_left_rotate(a, S3[s]);
        a += b;

        #if MD5_DEBUG
            std::cout << "A = " << a << "\n";
        #endif // MD5_DEBUG
    };
    inline void II(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int Xk, unsigned int s, unsigned int i) {
        #if MD5_DEBUG
            std::cout << "\nA: " << a << "\nB: " << b << "\nC: " << c << "\nD: " << d << "\nX[" << i - 48 << "]: " << Xk << "\ns: " << S4[s] << "\nT: " << T[i] << "\n";
        #endif // MD5_DEBUG

        a += I(b,c,d) + Xk + T[i];
        a = cyclic_left_rotate(a, S4[s]);
        a += b;

        #if MD5_DEBUG
            std::cout << "A = " << a << "\n";
        #endif // MD5_DEBUG
    };

    /*
     * Define my endian-ness.  Could not do in a portable manner using the
     * include files -- grumble.
     */
    #if MD5_BIG_ENDIAN

    /*
     * big endian - big is better
     */
    #define MD5_SWAP(n) (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

    #else

    /*
     * little endian
     */
    #define MD5_SWAP(n) (n)

    #endif // MD5_BIG_ENDIAN

    const char* HEX_STRING = "0123456789abcdef";    /* to convert to hex */
}

#endif /* ! __MD5_LOC_H__ */

#include <cassert>
#include <cstring>
#include <iostream>

namespace md5 {
    /****************************** Public Functions ******************************/

    /*
     * md5_t
     *
     * DESCRIPTION:
     *
     * Initialize structure containing state of MD5 computation. (RFC 1321,
     * 3.3: Step 3).  This is for progressive MD5 calculations only.  If
     * you have the complete string available, call it as below.
     * process should be called for each bunch of bytes and after the
     * last process call, finish should be called to get the signature.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * None.
     */
    md5_t::md5_t() {
        initialise();
    }

    /*
     * md5_t
     *
     * DESCRIPTION:
     *
     * This function is used to calculate a MD5 signature for a buffer of
     * bytes.  If you only have part of a buffer that you want to process
     * then md5_t, process, and finish should be used.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * buffer - A buffer of bytes whose MD5 signature we are calculating.
     *
     * input_length - The length of the buffer.
     *
     * signature - A 16 byte buffer that will contain the MD5 signature.
     */
    md5_t::md5_t(const void* input, const unsigned int input_length, void* signature) {
        /* initialize the computation context */
        initialise();

        /* process whole buffer but last input_length % MD5_BLOCK bytes */
        process(input, input_length);

        /* put result in desired memory area */
        finish(signature);
    }

    /*
     * process
     *
     * DESCRIPTION:
     *
     * This function is used to progressively calculate a MD5 signature some
     * number of bytes at a time.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * buffer - A buffer of bytes whose MD5 signature we are calculating.
     *
     * input_length - The length of the buffer.
     */
    void md5_t::process(const void* input, const unsigned int input_length) {
        if (!finished) {
            unsigned int processed = 0;

            /*
             * If we have any data stored from a previous call to process then we use these
             * bytes first, and the new data is large enough to create a complete block then
             * we process these bytes first.
             */
            if (stored_size && input_length + stored_size >= md5::BLOCK_SIZE) {
                unsigned char block[md5::BLOCK_SIZE];
                memcpy(block, stored, stored_size);
                memcpy(block + stored_size, input, md5::BLOCK_SIZE - stored_size);
                processed = md5::BLOCK_SIZE - stored_size;
                stored_size = 0;
                process_block(block);
            }

            /*
             * While there is enough data to create a complete block, process it.
             */
            while (processed + md5::BLOCK_SIZE <= input_length) {
                process_block((unsigned char*)input + processed);
                processed += md5::BLOCK_SIZE;
            }

            /*
             * If there are any unprocessed bytes left over that do not create a complete block
             * then we store these bytes for processing next time.
             */
            if (processed != input_length) {
                memcpy(stored + stored_size, (char*)input + processed, input_length - processed);
                stored_size += input_length - processed;
            } else {
                stored_size = 0;
            }
        } else {
            // throw error when trying to process after completion?
        }
    }

    /*
     * finish
     *
     * DESCRIPTION:
     *
     * Finish a progressing MD5 calculation and copy the resulting MD5
     * signature into the result buffer which should be 16 bytes
     * (MD5_SIZE).  After this call, the MD5 structure cannot process
	 * additional bytes.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature - A 16 byte buffer that will contain the MD5 signature.
     */
    void md5_t::finish(void* signature_) {
        if (!finished) {
            if (message_length[0] + stored_size < message_length[0])
                message_length[1]++;
            message_length[0] += stored_size;

            int pad = md5::BLOCK_SIZE - (sizeof(unsigned int) * 2) - stored_size;
            if (pad <= 0)
                pad += md5::BLOCK_SIZE;

            /*
             * Modified from a fixed array to this assignment and memset to be
             * more flexible with block-sizes -- Gray 10/97.
             */
            if (pad > 0) {
                stored[stored_size] = 0x80;
                if (pad > 1)
                    memset(stored + stored_size + 1, 0, pad - 1);
                stored_size += pad;
            }

            /*
             * Put the 64-bit file length in _bits_ (i.e. *8) at the end of the
             * buffer. appears to be in beg-endian format in the buffer?
             */
            unsigned int size_low = ((message_length[0] & 0x1FFFFFFF) << 3);
            memcpy(stored + stored_size, &size_low, sizeof(unsigned int));
            stored_size += sizeof(unsigned int);

            /* shift the high word over by 3 and add in the top 3 bits from the low */
            unsigned int size_high = (message_length[1] << 3) | ((message_length[0] & 0xE0000000) >> 29);
            memcpy(stored + stored_size, &size_high, sizeof(unsigned int));
            stored_size += sizeof(unsigned int);

            /*
             * process the last block of data.
             * if the length of the message was already exactly sized, then we have
             * 2 messages to process
             */
            process_block(stored);
            if (stored_size > md5::BLOCK_SIZE)
                process_block(stored + md5::BLOCK_SIZE);

            /* Arrange the results into a signature */
            get_result(static_cast<void*>(signature));

            /* store the signature into a readable sring */
            sig_to_string(signature, str, MD5_STRING_SIZE);

            if (signature_ != NULL) {
                memcpy(signature_, static_cast<void*>(signature), MD5_SIZE);
            }

            finished = true;
        } else {
            // add error?
        }
    }

    /*
     * get_sig
     *
     * DESCRIPTION:
     *
     * Retrieves the previously calculated signature from the MD5 object.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature_ - A 16 byte buffer that will contain the MD5 signature.
     */
    void md5_t::get_sig(void* signature_) {
        if (finished) {
            memcpy(signature_, signature, MD5_SIZE);
        } else {
            //error?
        }
    }

    /*
     * get_string
     *
     * DESCRIPTION:
     *
     * Retrieves the previously calculated signature from the MD5 object in
     * printable format.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * str_ - a string of characters which should be at least 33 bytes long
     * (2 characters per MD5 byte and 1 for the \0).
     */
    void md5_t::get_string(void* str_) {
        if (finished) {
            memcpy(str_, str, MD5_STRING_SIZE);
        } else {
            // error?
        }
    }

    /****************************** Private Functions ******************************/

    /*
     * initialise
     *
     * DESCRIPTION:
     *
     * Initialize structure containing state of MD5 computation. (RFC 1321,
     * 3.3: Step 3).
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * None.
     */
    void md5_t::initialise() {
        /*
         * ensures that unsigned int is 4 bytes on this platform, will need modifying
         * if we are to use on a different sized platform.
         */
        assert(MD5_SIZE == 16);

        A = 0x67452301;
        B = 0xefcdab89;
        C = 0x98badcfe;
        D = 0x10325476;

        message_length[0] = 0;
        message_length[1] = 0;
        stored_size = 0;

        finished = false;
    }

    /*
     * process_block
     *
     * DESCRIPTION:
     *
     * Process a block of bytes into a MD5 state structure.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * buffer - A buffer of bytes whose MD5 signature we are calculating.
     *
     * input_length - The length of the buffer.
     */
    void md5_t::process_block(const unsigned char* block) {
    /* Process each 16-word block. */

        /*
         * we check for when the lower word rolls over, and increment the
         * higher word. we do not need to worry if the higher word rolls over
         * as only the two words we maintain are needed in the function later
         */
        if (message_length[0] + md5::BLOCK_SIZE < message_length[0])
            message_length[1]++;
        message_length[0] += BLOCK_SIZE;

        // Copy the block into X. */
        unsigned int X[16];
        for (unsigned int i = 0; i < 16; i++) {
            memcpy(X + i, block + 4 * i, 4);
        }

        /* Save A as AA, B as BB, C as CC, and D as DD. */
        unsigned int AA = A, BB = B, CC = C, DD = D;

        /* Round 1
         * Let [abcd k s i] denote the operation
         * a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  0  7  1]  [DABC  1 12  2]  [CDAB  2 17  3]  [BCDA  3 22  4]
         * [ABCD  4  7  5]  [DABC  5 12  6]  [CDAB  6 17  7]  [BCDA  7 22  8]
         * [ABCD  8  7  9]  [DABC  9 12 10]  [CDAB 10 17 11]  [BCDA 11 22 12]
         * [ABCD 12  7 13]  [DABC 13 12 14]  [CDAB 14 17 15]  [BCDA 15 22 16]
         */
        md5::FF(A, B, C, D, X[0 ], 0, 0 );
        md5::FF(D, A, B, C, X[1 ], 1, 1 );
        md5::FF(C, D, A, B, X[2 ], 2, 2 );
        md5::FF(B, C, D, A, X[3 ], 3, 3 );
        md5::FF(A, B, C, D, X[4 ], 0, 4 );
        md5::FF(D, A, B, C, X[5 ], 1, 5 );
        md5::FF(C, D, A, B, X[6 ], 2, 6 );
        md5::FF(B, C, D, A, X[7 ], 3, 7 );
        md5::FF(A, B, C, D, X[8 ], 0, 8 );
        md5::FF(D, A, B, C, X[9 ], 1, 9 );
        md5::FF(C, D, A, B, X[10], 2, 10);
        md5::FF(B, C, D, A, X[11], 3, 11);
        md5::FF(A, B, C, D, X[12], 0, 12);
        md5::FF(D, A, B, C, X[13], 1, 13);
        md5::FF(C, D, A, B, X[14], 2, 14);
        md5::FF(B, C, D, A, X[15], 3, 15);

        /* Round 2
         * Let [abcd k s i] denote the operation
         * a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  1  5 17]  [DABC  6  9 18]  [CDAB 11 14 19]  [BCDA  0 20 20]
         * [ABCD  5  5 21]  [DABC 10  9 22]  [CDAB 15 14 23]  [BCDA  4 20 24]
         * [ABCD  9  5 25]  [DABC 14  9 26]  [CDAB  3 14 27]  [BCDA  8 20 28]
         * [ABCD 13  5 29]  [DABC  2  9 30]  [CDAB  7 14 31]  [BCDA 12 20 32]
         */
        md5::GG(A, B, C, D, X[1 ], 0, 16);
        md5::GG(D, A, B, C, X[6 ], 1, 17);
        md5::GG(C, D, A, B, X[11], 2, 18);
        md5::GG(B, C, D, A, X[0 ], 3, 19);
        md5::GG(A, B, C, D, X[5 ], 0, 20);
        md5::GG(D, A, B, C, X[10], 1, 21);
        md5::GG(C, D, A, B, X[15], 2, 22);
        md5::GG(B, C, D, A, X[4 ], 3, 23);
        md5::GG(A, B, C, D, X[9 ], 0, 24);
        md5::GG(D, A, B, C, X[14], 1, 25);
        md5::GG(C, D, A, B, X[3 ], 2, 26);
        md5::GG(B, C, D, A, X[8 ], 3, 27);
        md5::GG(A, B, C, D, X[13], 0, 28);
        md5::GG(D, A, B, C, X[2 ], 1, 29);
        md5::GG(C, D, A, B, X[7 ], 2, 30);
        md5::GG(B, C, D, A, X[12], 3, 31);

        /* Round 3
         * Let [abcd k s i] denote the operation
         * a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  5  4 33]  [DABC  8 11 34]  [CDAB 11 16 35]  [BCDA 14 23 36]
         * [ABCD  1  4 37]  [DABC  4 11 38]  [CDAB  7 16 39]  [BCDA 10 23 40]
         * [ABCD 13  4 41]  [DABC  0 11 42]  [CDAB  3 16 43]  [BCDA  6 23 44]
         * [ABCD  9  4 45]  [DABC 12 11 46]  [CDAB 15 16 47]  [BCDA  2 23 48]
         */
        md5::HH(A, B, C, D, X[5 ], 0, 32);
        md5::HH(D, A, B, C, X[8 ], 1, 33);
        md5::HH(C, D, A, B, X[11], 2, 34);
        md5::HH(B, C, D, A, X[14], 3, 35);
        md5::HH(A, B, C, D, X[1 ], 0, 36);
        md5::HH(D, A, B, C, X[4 ], 1, 37);
        md5::HH(C, D, A, B, X[7 ], 2, 38);
        md5::HH(B, C, D, A, X[10], 3, 39);
        md5::HH(A, B, C, D, X[13], 0, 40);
        md5::HH(D, A, B, C, X[0 ], 1, 41);
        md5::HH(C, D, A, B, X[3 ], 2, 42);
        md5::HH(B, C, D, A, X[6 ], 3, 43);
        md5::HH(A, B, C, D, X[9 ], 0, 44);
        md5::HH(D, A, B, C, X[12], 1, 45);
        md5::HH(C, D, A, B, X[15], 2, 46);
        md5::HH(B, C, D, A, X[2 ], 3, 47);

        /* Round 4
         * Let [abcd k s i] denote the operation
         * a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s)
         * Do the following 16 operations
         * [ABCD  0  6 49]  [DABC  7 10 50]  [CDAB 14 15 51]  [BCDA  5 21 52]
         * [ABCD 12  6 53]  [DABC  3 10 54]  [CDAB 10 15 55]  [BCDA  1 21 56]
         * [ABCD  8  6 57]  [DABC 15 10 58]  [CDAB  6 15 59]  [BCDA 13 21 60]
         * [ABCD  4  6 61]  [DABC 11 10 62]  [CDAB  2 15 63]  [BCDA  9 21 64]
         */
        md5::II(A, B, C, D, X[0 ], 0, 48);
        md5::II(D, A, B, C, X[7 ], 1, 49);
        md5::II(C, D, A, B, X[14], 2, 50);
        md5::II(B, C, D, A, X[5 ], 3, 51);
        md5::II(A, B, C, D, X[12], 0, 52);
        md5::II(D, A, B, C, X[3 ], 1, 53);
        md5::II(C, D, A, B, X[10], 2, 54);
        md5::II(B, C, D, A, X[1 ], 3, 55);
        md5::II(A, B, C, D, X[8 ], 0, 56);
        md5::II(D, A, B, C, X[15], 1, 57);
        md5::II(C, D, A, B, X[6 ], 2, 58);
        md5::II(B, C, D, A, X[13], 3, 59);
        md5::II(A, B, C, D, X[4 ], 0, 60);
        md5::II(D, A, B, C, X[11], 1, 61);
        md5::II(C, D, A, B, X[2 ], 2, 62);
        md5::II(B, C, D, A, X[9 ], 3, 63);

        /* Then perform the following additions. (That is increment each
        of the four registers by the value it had before this block
        was started.) */
        A += AA;
        B += BB;
        C += CC;
        D += DD;
    }

    /*
     * get_result
     *
     * DESCRIPTION:
     *
     * Copy the resulting MD5 signature into the first 16 bytes (MD5_SIZE)
     * of the result buffer.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * result - A 16 byte buffer that will contain the MD5 signature.
     */
    void md5_t::get_result(void *result) {
        memcpy((char*)result, &A, sizeof(unsigned int));
        memcpy((char*)result + sizeof(unsigned int), &B, sizeof(unsigned int));
        memcpy((char*)result + 2 * sizeof(unsigned int), &C, sizeof(unsigned int));
        memcpy((char*)result + 3 * sizeof(unsigned int), &D, sizeof(unsigned int));
    }

    /****************************** Exported Functions ******************************/

    /*
     * sig_to_string
     *
     * DESCRIPTION:
     *
     * Convert a MD5 signature in a 16 byte buffer into a hexadecimal string
     * representation.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature_ - a 16 byte buffer that contains the MD5 signature.
     *
     * str_ - a string of charactes which should be at least 33 bytes long (2
     * characters per MD5 byte and 1 for the \0).
     *
     * str_len - the length of the string.
     */
    void sig_to_string(const void* signature_, char* str_, const int str_len) {
        unsigned char* sig_p;
        char* str_p;
        char* max_p;
        unsigned int high, low;

        str_p = str_;
        max_p = str_ + str_len;

        for (sig_p = (unsigned char*)signature_; sig_p < (unsigned char*)signature_ + MD5_SIZE; sig_p++) {
            high = *sig_p / 16;
            low = *sig_p % 16;
            /* account for 2 chars */
            if (str_p + 1 >= max_p) {
                break;
            }
            *str_p++ = md5::HEX_STRING[high];
            *str_p++ = md5::HEX_STRING[low];
        }
        /* account for 2 chars */
        if (str_p < max_p) {
            *str_p++ = '\0';
        }
    }

    /*
     * sig_from_string
     *
     * DESCRIPTION:
     *
     * Convert a MD5 signature from a hexadecimal string representation into
     * a 16 byte buffer.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature_ - A 16 byte buffer that will contain the MD5 signature.
     *
     * str_ - A string of charactes which _must_ be at least 32 bytes long (2
     * characters per MD5 byte).
     */
    void sig_from_string(void* signature_, const char* str_) {
        unsigned char *sig_p;
        const char *str_p;
        char* hex;
        unsigned int high, low, val;

        hex = (char*)md5::HEX_STRING;
        sig_p = static_cast<unsigned char*>(signature_);

        for (str_p = str_; str_p < str_ + MD5_SIZE * 2; str_p += 2) {
            high = (unsigned int)(strchr(hex, *str_p) - hex);
            low = (unsigned int)(strchr(hex, *(str_p + 1)) - hex);
            val = high * 16 + low;
            *sig_p++ = val;
        }
    }
} // namespace md5


/*
Copyright (c) 2011, Micael Hildenborg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
* Neither the name of Micael Hildenborg nor the
names of its contributors may be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY Micael Hildenborg ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Micael Hildenborg BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef SHA1_DEFINED
#define SHA1_DEFINED

namespace sha1
{

    /**
    @param src points to any kind of data to be hashed.
    @param bytelength the number of bytes to hash from the src pointer.
    @param hash should point to a buffer of at least 20 bytes of size for storing the sha1 result in.
    */
    static void calc(const void* src, const int bytelength, unsigned char* hash);

    /**
    @param hash is 20 bytes of sha1 hash. This is the same data that is the result from the calc function.
    @param hexstring should point to a buffer of at least 41 bytes of size for storing the hexadecimal representation of the hash. A zero will be written at position 40, so the buffer will be a valid zero ended string.
    */
    static void toHexString(const unsigned char* hash, char* hexstring);

} // namespace sha1

#endif // SHA1_DEFINED

/*
Copyright (c) 2011, Micael Hildenborg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
* Neither the name of Micael Hildenborg nor the
names of its contributors may be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY Micael Hildenborg ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Micael Hildenborg BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
Contributors:
Gustav
Several members in the gamedev.se forum.
Gregory Petrosyan
*/

namespace sha1
{
    namespace // local
    {
        // Rotate an integer value to left.
        inline const unsigned int rol(const unsigned int value,
                                      const unsigned int steps)
        {
            return ((value << steps) | (value >> (32 - steps)));
        }

        // Sets the first 16 integers in the buffert to zero.
        // Used for clearing the W buffert.
        inline void clearWBuffert(unsigned int* buffert)
        {
            for (int pos = 16; --pos >= 0;)
            {
                buffert[pos] = 0;
            }
        }

        void innerHash(unsigned int* result, unsigned int* w)
        {
            unsigned int a = result[0];
            unsigned int b = result[1];
            unsigned int c = result[2];
            unsigned int d = result[3];
            unsigned int e = result[4];

            int round = 0;

#define sha1macro(func,val) \
                                    { \
                const unsigned int t = rol(a, 5) + (func) + e + val + w[round]; \
                                e = d; \
                                d = c; \
                                c = rol(b, 30); \
                                b = a; \
                                a = t; \
                                    }

            while (round < 16)
            {
                sha1macro((b & c) | (~b & d), 0x5a827999)
                    ++round;
            }
            while (round < 20)
            {
                w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
                sha1macro((b & c) | (~b & d), 0x5a827999)
                    ++round;
            }
            while (round < 40)
            {
                w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
                sha1macro(b ^ c ^ d, 0x6ed9eba1)
                    ++round;
            }
            while (round < 60)
            {
                w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
                sha1macro((b & c) | (b & d) | (c & d), 0x8f1bbcdc)
                    ++round;
            }
            while (round < 80)
            {
                w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
                sha1macro(b ^ c ^ d, 0xca62c1d6)
                    ++round;
            }

#undef sha1macro

            result[0] += a;
            result[1] += b;
            result[2] += c;
            result[3] += d;
            result[4] += e;
        }
    } // namespace

    static void calc(const void* src, const int bytelength, unsigned char* hash)
    {
        // Init the result array.
        unsigned int result[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};

        // Cast the void src pointer to be the byte array we can work with.
        const unsigned char* sarray = (const unsigned char*)src;

        // The reusable round buffer
        unsigned int w[80];

        // Loop through all complete 64byte blocks.
        const int endOfFullBlocks = bytelength - 64;
        int endCurrentBlock;
        int currentBlock = 0;

        while (currentBlock <= endOfFullBlocks)
        {
            endCurrentBlock = currentBlock + 64;

            // Init the round buffer with the 64 byte block data.
            for (int roundPos = 0; currentBlock < endCurrentBlock; currentBlock += 4)
            {
                // This line will swap endian on big endian and keep endian on little endian.
                w[roundPos++] = (unsigned int)sarray[currentBlock + 3]
                    | (((unsigned int)sarray[currentBlock + 2]) << 8)
                    | (((unsigned int)sarray[currentBlock + 1]) << 16)
                    | (((unsigned int)sarray[currentBlock]) << 24);
            }
            innerHash(result, w);
        }

        // Handle the last and not full 64 byte block if existing.
        endCurrentBlock = bytelength - currentBlock;
        clearWBuffert(w);
        int lastBlockBytes = 0;
        for (; lastBlockBytes < endCurrentBlock; ++lastBlockBytes)
        {
            w[lastBlockBytes >> 2] |= (unsigned int)sarray[lastBlockBytes + currentBlock] << ((3 - (lastBlockBytes & 3)) << 3);
        }
        w[lastBlockBytes >> 2] |= 0x80 << ((3 - (lastBlockBytes & 3)) << 3);
        if (endCurrentBlock >= 56)
        {
            innerHash(result, w);
            clearWBuffert(w);
        }
        w[15] = bytelength << 3;
        innerHash(result, w);

        // Store hash in result pointer, and make sure we get in in the correct order on both endian models.
        for (int hashByte = 20; --hashByte >= 0;)
        {
            hash[hashByte] = (result[hashByte >> 2] >> (((3 - hashByte) & 0x3) << 3)) & 0xff;
        }
    }

    static void toHexString(const unsigned char* hash, char* hexstring)
    {
        const char hexDigits[] = {"0123456789abcdef"};

        for (int hashByte = 20; --hashByte >= 0;)
        {
            hexstring[hashByte << 1] = hexDigits[(hash[hashByte] >> 4) & 0xf];
            hexstring[(hashByte << 1) + 1] = hexDigits[hash[hashByte] & 0xf];
        }
        hexstring[40] = 0;
    }
} // namespace sha1

/*
base64.cpp and base64.h

Copyright (C) 2004-2008 Rene Nyffenegger

This source code is provided 'as-is', without any express or implied
warranty. In no event will the author be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this source code must not be misrepresented; you must not
claim that you wrote the original source code. If you use this source code
in a product, an acknowledgment in the product documentation would be
appreciated but is not required.

2. Altered source versions must be plainly marked as such, and must not be
misrepresented as being the original source code.

3. This notice may not be removed or altered from any source distribution.

Rene Nyffenegger rene.nyffenegger@adp-gmbh.ch
*/

#include <iostream>

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool is_base64(uint8_t c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

namespace outils
{
#if defined(WIN32)
    std::wstring utf8ToWide(const std::string& utf8)
    {
        auto requiredSize = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
        std::wstring ret;
        ret.resize(requiredSize - 1);
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, (LPWSTR)ret.c_str(), requiredSize);
        return std::move(ret);
    }

    std::string wideToUtf8(const std::wstring& wide)
    {
        auto requiredSize = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string ret;
        ret.resize(requiredSize - 1);
        WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, (LPSTR)ret.c_str(), requiredSize, nullptr, nullptr);
        return std::move(ret);
    }
#endif

    std::vector<std::string> splitString(const std::string& in_string, char in_delimiter, bool in_removeEmptyElements)
    {
        std::vector<std::string> elems;
        unsigned int start = 0;
        unsigned int end = 0;
        for (; end < in_string.length(); ++end)
        {
            if (in_string[end] == in_delimiter)
            {
                if (end - start || !in_removeEmptyElements)
                {
                    elems.push_back(in_string.substr(start, end - start));
                }
                start = end + 1;
            }
        }
        if (!in_removeEmptyElements && start == in_string.length())
        {
            elems.push_back("");
        }
        if (start < in_string.length())
        {
            if (end - start || !in_removeEmptyElements)
            {
                elems.push_back(in_string.substr(start, end - start));
            }
        }
        return elems;
    }

    std::vector<std::string> splitString(const std::string& in_string, const std::string& in_delimiters)
    {
        std::vector<std::string> elems;
        unsigned int start = 0;
        unsigned int end = 0;
        for (; end < in_string.length(); ++end)
        {
            for (auto c : in_delimiters)
            {
                if (in_string[end] == c)
                {
                    if (end - start)
                    {
                        elems.push_back(in_string.substr(start, end - start));
                    }
                    start = end + 1;
                }
            }
        }
        if (start == in_string.length())
        {
            elems.push_back("");
        }
        if (start < in_string.length())
        {
            if (end - start)
            {
                elems.push_back(in_string.substr(start, end - start));
            }
        }
        return elems;
    }

    std::string removeChars(const std::string& str, const std::string& charsToRemove)
    {
        auto ret = str;
        for (decltype(charsToRemove.size()) i = 0; i < charsToRemove.size(); ++i)
        {
            ret.erase(remove(ret.begin(), ret.end(), charsToRemove[i]), ret.end());
        }
        return ret;
    }

    std::string toUpper(const std::string& str)
    {
        auto ret = str;
        std::transform(ret.begin(), ret.end(), ret.begin(), ::toupper);
        return ret;
    }

    std::string toLower(const std::string& str)
    {
        auto ret = str;
        std::transform(ret.begin(), ret.end(), ret.begin(), ::tolower);
        return ret;
    }

    std::string trim(const std::string& str)
    {
        auto s = str.find_first_not_of(" \t\n\r");
        if (s == std::string::npos)
        {
            return "";
        }
        std::string ret;
        if (s > 0)
        {
            ret = str.substr(s);
        }
        else
        {
            ret = str;
        }
        s = ret.find_last_not_of(" \t\n\r");
        return ret.substr(0, s + 1);
    }

    size_t utf8Length(const std::string& str)
    {
        int len = 0;
        auto s = str.data();
        while (*s) len += (*s++ & 0xc0) != 0x80;
        return len;
    }

    size_t utf8Pos(const std::string& str, size_t pos)
    {
        auto s = str.data();
        while (*s && pos)
        {
            if (*s & 0x80)
            {
                if ((*s & 0xE0) == 0xC0)
                {
                    ++s;
                }
                else if ((*s & 0xF0) == 0xE0)
                {
                    s += 2;
                }
                else
                {
                    s += 3;
                }
            }
            --pos;
            ++s;
        }

        return s - str.data();
    }

    //--- Regex
    void stripOutComments(std::string& source)
    {
        // Group
        std::smatch m1;
        std::smatch m2;
        size_t offset = 0;
        while (std::regex_search(source.cbegin() + offset, source.cend(), m1, std::regex("\\/\\*")))
        {
            offset += m1.position();
            if (std::regex_search(source.cbegin() + offset, source.cend(), m2, std::regex("\\*\\/")))
            {
                source.erase(source.begin() + offset,
                             source.begin() + offset + m2.position() + m2.length());
            }
            else break;
        }

        // Single
        offset = 0;
        while (std::regex_search(source.cbegin() + offset, source.cend(), m1, std::regex("\\/\\/.*")))
        {
            offset += m1.position();
            source.erase(source.begin() + offset,
                         source.begin() + offset + m1.length());
        }
    }

    std::string stripOutComments(const std::string& source)
    {
        auto ret = source;
        stripOutComments(ret);
        return std::move(ret);
    }

    void replace(std::string& source, const std::string& reg, const std::string& substitution)
    {
        source = std::regex_replace(source, std::regex(reg), substitution);
    }

    std::string replace(const std::string& source, const std::string& reg, const std::string& substitution)
    {
        auto ret = source;
        replace(ret, reg, substitution);
        return std::move(ret);
    }

    std::string findFile(const std::string& name, const std::string& lookIn, bool deepSearch, bool ignoreCase)
    {
        DIR* dir;
        struct dirent* ent;
        if ((dir = opendir(lookIn.c_str())) != NULL)
        {
            while ((ent = readdir(dir)) != NULL)
            {
                if (!strcmp(ent->d_name, "."))
                {
                    continue;
                }
                else if (!strcmp(ent->d_name, ".."))
                {
                    continue;
                }

                if (ignoreCase)
                {
                    if (stricmp(name.c_str(), ent->d_name) == 0)
                    {
                        auto ret = lookIn + "/" + ent->d_name;
                        closedir(dir);
                        return ret;
                    }
                }
                else
                {
                    if (name == ent->d_name)
                    {
                        auto ret = lookIn + "/" + ent->d_name;
                        closedir(dir);
                        return ret;
                    }
                }

                if (ent->d_type & DT_DIR && deepSearch)
                {
                    auto ret = findFile(name, lookIn + "/" + ent->d_name, deepSearch, ignoreCase);
                    if (!ret.empty())
                    {
                        closedir(dir);
                        return ret;
                    }
                }
            }
            closedir(dir);
        }

        return "";
    }

    std::vector<std::string> findAllFiles(const std::string& lookIn, const std::string& extension, bool deepSearch)
    {
        std::vector<std::string> ret;

        bool all = extension == "*";
        auto upExt = toUpper(extension);
        DIR* dir;
        struct dirent* ent;
        if ((dir = opendir(lookIn.c_str())) != NULL)
        {
            while ((ent = readdir(dir)) != NULL)
            {
                if (!strcmp(ent->d_name, "."))
                {
                    continue;
                }
                else if (!strcmp(ent->d_name, ".."))
                {
                    continue;
                }

                if (ent->d_type & DT_DIR)
                {
                    if (deepSearch)
                    {
                        auto ret2 = findAllFiles(lookIn + "/" + ent->d_name, extension, deepSearch);
                        ret.insert(ret.end(), ret2.begin(), ret2.end());
                    }
                }
                else
                {
                    if (all)
                    {
                        ret.push_back(lookIn + "/" + ent->d_name);
                    }
                    else if (toUpper(getExtension(ent->d_name)) == upExt)
                    {
                        ret.push_back(lookIn + "/" + ent->d_name);
                    }
                }
            }
            closedir(dir);
        }

        return std::move(ret);
    }

    std::string getPath(const std::string& filename)
    {
        return filename.substr(0, filename.find_last_of("\\/"));
    }

    std::string getFilename(const std::string& path)
    {
        auto pos = path.find_last_of("\\/");
        if (pos == std::string::npos) return path;
        return path.substr(pos + 1);
    }

    std::string getPathWithoutExtension(const std::string& path)
    {
        auto pos = path.find_last_of('.');
        if (pos == std::string::npos) return path;
        return path.substr(0, pos);
    }

    std::string getFilenameWithoutExtension(const std::string& path)
    {
        auto filename = getFilename(path);
        auto pos = filename.find_last_of('.');
        if (pos == std::string::npos) return filename;
        return filename.substr(0, pos);
    }

    std::string getExtension(const std::string& filename)
    {
        auto pos = filename.find_last_of('.');
        if (pos == std::string::npos) return "";
        return toUpper(filename.substr(pos + 1));
    }

    std::string getParentFolderName(const std::string& filename)
    {
        auto path = getPath(filename);
        if (path.empty()) return "";
        return path.substr(0, path.find_last_of("\\/"));
    }

    std::string getSavePath(const std::string& appName)
    {
#if defined(WIN32)
        PWSTR path = NULL;
        HRESULT r;

        r = SHGetKnownFolderPath(FOLDERID_RoamingAppData, KF_FLAG_CREATE, NULL, &path);
        if (path != NULL)
        {
            auto ret = wideToUtf8(path) + "/" + appName + "/";
            CreateDirectoryA(ret.c_str(), NULL);
            CoTaskMemFree(path);
            std::replace(ret.begin(), ret.end(), '\\', '/');
            return ret;
        }

        return "./";
#else
        return "./";
#endif
    }

    std::string makeRelativePath(const std::string& in_path, const std::string& in_relativeTo)
    {
        auto path = in_path;
        if (path.size() >= 2 && path[0] == '.' && (path[1] == '\\' || path[1] == '/'))
            path = path.substr(2);
        std::replace(path.begin(), path.end(), '\\', '/');
        auto pathSplit = splitString(path, '/');

        auto relativeTo = in_relativeTo;
        std::replace(relativeTo.begin(), relativeTo.end(), '\\', '/');
        auto relativeSplit = splitString(relativeTo, '/');

        while (pathSplit.size() && relativeSplit.size() && pathSplit.front() == relativeSplit.front())
        {
            pathSplit.erase(pathSplit.begin());
            relativeSplit.erase(relativeSplit.begin());
        }

        std::stringstream ss;
        bool bFirst = true;
        for (auto& folder : relativeSplit)
        {
            if (!bFirst) ss << "/";
            bFirst = false;
            ss << "..";
        }
        for (auto& folder : pathSplit)
        {
            if (!bFirst) ss << "/";
            bFirst = false;
            ss << folder;
        }
        return std::move(ss.str());
    }

    std::vector<uint8_t> getFileData(const std::string& filename)
    {
        std::ifstream file(filename, std::ios::binary);
        std::vector<uint8_t> data = { std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>() };
        return std::move(data);
    }

    std::string getFileString(const std::string& filename)
    {
        auto data = getFileData(filename);
        std::string str((const char* const)data.data(), data.size());
        return std::move(str);
    }

#if defined(WIN32)
    bool fileExists(const std::string& filename)
    {
        WIN32_FIND_DATAA FindFileData;
        HANDLE handle = FindFirstFileA(filename.c_str(), &FindFileData);
        bool found = handle != INVALID_HANDLE_VALUE;
        if (found)
        {
            //FindClose(&handle); this will crash
            FindClose(handle);
        }
        return found;
    }

    std::string showOpenDialog(HWND hwndOwner, const std::string& caption, const FileTypes& extensions, const std::string& defaultFilename)
    {
        auto windowHandle = hwndOwner;
        char szFileName[MAX_PATH] = { 0 };
        memcpy(szFileName, defaultFilename.c_str(), std::min<size_t>(defaultFilename.size(), static_cast<size_t>(MAX_PATH - 1)));

        OPENFILENAMEA ofn = { 0 };
        ofn.lStructSize = sizeof(OPENFILENAMEA);
        ofn.hwndOwner = windowHandle;
        ofn.lStructSize = sizeof(ofn);
        ofn.lpstrFile = szFileName;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

        size_t totalCount = 0;
        for (auto& fileType : extensions)
        {
            totalCount += fileType.typeName.size();
            totalCount += fileType.extension.size();
        }

        char* szFilters = new char[21 + totalCount * 3 + 9 * extensions.size()];

        size_t currentOffset = 0;
        for (auto& fileType : extensions)
        {
            memcpy(szFilters + currentOffset, fileType.typeName.c_str(), fileType.typeName.size());
            currentOffset += fileType.typeName.size();
            memcpy(szFilters + currentOffset, " (*.", 4);
            currentOffset += 4;
            memcpy(szFilters + currentOffset, fileType.extension.c_str(), fileType.extension.size());
            currentOffset += fileType.extension.size();
            memcpy(szFilters + currentOffset, ")\0*.", 4);
            currentOffset += 4;
            memcpy(szFilters + currentOffset, fileType.extension.c_str(), fileType.extension.size());
            currentOffset += fileType.extension.size();
            memcpy(szFilters + currentOffset, "\0", 1);
            currentOffset += 1;
        }
        memcpy(szFilters + currentOffset, "All Files (*.*)\0*.*\0\0", 21);

        ofn.lpstrFilter = szFilters;
        std::string defaultExtension = extensions[0].extension;
        ofn.lpstrDefExt = defaultExtension.c_str();
        ofn.lpstrTitle = caption.c_str();

        // PNG Files (*.PNG)\0*.PNG\0All Files (*.*)\0*.*\0

        GetOpenFileNameA(&ofn);

        delete[] szFilters;

        return ofn.lpstrFile;
    }

    std::string showSaveAsDialog(HWND hwndOwner, const std::string& caption, const FileTypes& extensions, const std::string& defaultFilename)
    {
        auto windowHandle = hwndOwner;
        char szFileName[MAX_PATH] = { 0 };
        memcpy(szFileName, defaultFilename.c_str(), std::min<size_t>(defaultFilename.size(), static_cast<size_t>(MAX_PATH - 1)));

        OPENFILENAMEA ofn = { 0 };
        ofn.lStructSize = sizeof(OPENFILENAMEA);
        ofn.hwndOwner = windowHandle;
        ofn.lStructSize = sizeof(ofn);
        ofn.lpstrFile = szFileName;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

        size_t totalCount = 0;
        for (auto& fileType : extensions)
        {
            totalCount += fileType.typeName.size();
            totalCount += fileType.extension.size();
        }

        char* szFilters = new char[21 + totalCount * 3 + 9 * extensions.size()];

        size_t currentOffset = 0;
        for (auto& fileType : extensions)
        {
            memcpy(szFilters + currentOffset, fileType.typeName.c_str(), fileType.typeName.size());
            currentOffset += fileType.typeName.size();
            memcpy(szFilters + currentOffset, " (*.", 4);
            currentOffset += 4;
            memcpy(szFilters + currentOffset, fileType.extension.c_str(), fileType.extension.size());
            currentOffset += fileType.extension.size();
            memcpy(szFilters + currentOffset, ")\0*.", 4);
            currentOffset += 4;
            memcpy(szFilters + currentOffset, fileType.extension.c_str(), fileType.extension.size());
            currentOffset += fileType.extension.size();
            memcpy(szFilters + currentOffset, "\0", 1);
            currentOffset += 1;
        }
        memcpy(szFilters + currentOffset, "All Files (*.*)\0*.*\0\0", 21);

        ofn.lpstrFilter = szFilters;
        std::string defaultExtension = extensions[0].extension;
        ofn.lpstrDefExt = defaultExtension.c_str();
        ofn.lpstrTitle = caption.c_str();

        // PNG Files (*.PNG)\0*.PNG\0All Files (*.*)\0*.*\0

        GetSaveFileNameA(&ofn);

        delete[] szFilters;

        return ofn.lpstrFile;
    }
#endif

    std::string showOpenFolderDialog(const std::string& caption, const std::string& defaultPath)
    {
        auto pPath = tinyfd_selectFolderDialog(caption.c_str(), defaultPath.c_str());
        if (!pPath) return "";
        return pPath;
    }

    bool createFolder(const std::string& fullPath)
    {
#if defined(WIN32)
        std::string withBackwardSlashes = fullPath;
        replace(withBackwardSlashes, "/", "\\");
        return system(("mkdir " + withBackwardSlashes).c_str()) == 0;
#else
        return system(("mkdir " + fullPath).c_str()) == 0;
#endif
    }

    bool copyFile(const std::string& from, const std::string& to)
    {
#if defined(WIN32)
        std::string withBackwardSlashes_from = from;
        replace(withBackwardSlashes_from, "/", "\\");
        std::string withBackwardSlashes_to = to;
        replace(withBackwardSlashes_to, "/", "\\");
        std::ifstream src(withBackwardSlashes_from, std::ios::binary);
        std::ofstream dst(withBackwardSlashes_to, std::ios::binary);
        if (!src.is_open() || !dst.is_open()) return false;
        dst << src.rdbuf();
        src.close();
        dst.close();
        return true;
#else
        return system(("cp " + from + " " + to).c_str()) == 0;
#endif
    }

    bool createTextFile(const std::string& path, const std::string& content)
    {
#if defined(WIN32)
        std::string withBackwardSlashes = path;
        replace(withBackwardSlashes, "/", "\\");
        std::ofstream dst(withBackwardSlashes, std::ios::binary);
        if (!dst.is_open()) return false;
        dst << content;
        dst.close();
        return true;
#else
        std::ofstream dst(path, std::ios::binary);
        if (!dst.is_open()) return false;
        dst << content;
        dst.close();
        return true;
#endif
    }

    void showInExplorer(const std::string& path)
    {
#if defined(WIN32)
        std::string pathReverseSlash = path;
        std::replace(pathReverseSlash.begin(), pathReverseSlash.end(), '/', '\\');
        ITEMIDLIST *pidl = ILCreateFromPath(pathReverseSlash.c_str());
        if (pidl)
        {
            SHOpenFolderAndSelectItems(pidl, 0, 0, 0);
            ILFree(pidl);
        }
#elif defined(__APPLE__)
        system(("open " + path).c_str());
#else
        system(("xdg-open " + path).c_str());
#endif
    }

    void openFile(const std::string& path)
    {
#if defined(WIN32)
        ShellExecuteA(0, 0, path.c_str(), 0, 0 , SW_SHOW);
#endif
    }

    MessageBoxReturn showMessageBox(const std::string& title, const std::string& message, MessageBoxType type, MessageBoxLevel level)
    {
        const char* typeStr;
        switch (type)
        {
            case MessageBoxType::Ok: typeStr = "ok"; break;
            case MessageBoxType::OkCancel: typeStr = "okcancel"; break;
            case MessageBoxType::YesNo: typeStr = "yesno"; break;
            case MessageBoxType::YesNoCancel: typeStr = "yesnocancel"; break;
        }

        const char* iconStr;
        switch (level)
        {
            case MessageBoxLevel::Info: iconStr = "info"; break;
            case MessageBoxLevel::Warning: iconStr = "warning"; break;
            case MessageBoxLevel::Error: iconStr = "error"; break;
            case MessageBoxLevel::Question: iconStr = "question"; break;
        }

        auto ret = tinyfd_messageBox(
            title.c_str(),
            message.c_str(),
            typeStr,
            iconStr,
            1);

        return (MessageBoxReturn)ret;
    }

    void writeInt8(int8_t val, FILE* pFile)
    {
        fwrite(&val, sizeof(int8_t), 1, pFile);
    }

    void writeUInt8(uint8_t val, FILE* pFile)
    {
        fwrite(&val, sizeof(uint8_t), 1, pFile);
    }

    void writeInt16(int16_t val, FILE* pFile)
    {
        fwrite(&val, sizeof(int16_t), 1, pFile);
    }

    void writeUInt16(uint16_t val, FILE* pFile)
    {
        fwrite(&val, sizeof(uint16_t), 1, pFile);
    }

    void writeInt32(int32_t val, FILE* pFile)
    {
        fwrite(&val, sizeof(int32_t), 1, pFile);
    }

    void writeUInt32(uint32_t val, FILE* pFile)
    {
        fwrite(&val, sizeof(uint32_t), 1, pFile);
    }

    void writeInt64(int64_t val, FILE* pFile)
    {
        fwrite(&val, sizeof(int64_t), 1, pFile);
    }

    void writeUInt64(uint64_t val, FILE* pFile)
    {
        fwrite(&val, sizeof(uint64_t), 1, pFile);
    }

    void writeFloat(float val, FILE* pFile)
    {
        fwrite(&val, sizeof(float), 1, pFile);
    }

    void writeDouble(double val, FILE* pFile)
    {
        fwrite(&val, sizeof(double), 1, pFile);
    }

    void writeBool(bool val, FILE* pFile)
    {
        uint8_t vali = val ? 1 : 0;
        fwrite(&vali, sizeof(uint8_t), 1, pFile);
    }

    void writeString(const std::string& val, FILE* pFile)
    {
        fwrite(val.c_str(), 1, val.size() + 1, pFile);
    }

    void writeFloat2(const float* val, FILE* pFile)
    {
        fwrite(val, sizeof(float), 2, pFile);
    }

    void writeFloat3(const float* val, FILE* pFile)
    {
        fwrite(val, sizeof(float), 3, pFile);
    }

    void writeFloat4(const float* val, FILE* pFile)
    {
        fwrite(val, sizeof(float), 4, pFile);
    }

    void writeInt2(const int* val, FILE* pFile)
    {
        int32_t vals[2] = { (int32_t)val[0], (int32_t)val[1] };
        fwrite(vals, sizeof(int32_t), 2, pFile);
    }

    void writeInt4(const int* val, FILE* pFile)
    {
        int32_t vals[4] = { (int32_t)val[0], (int32_t)val[1], (int32_t)val[2], (int32_t)val[3] };
        fwrite(vals, sizeof(int32_t), 4, pFile);
    }

    void writeMatrix4x4(const float* val, FILE* pFile)
    {
        fwrite(val, sizeof(float), 16, pFile);
    }

    int8_t readInt8(FILE* pFile)
    {
        int8_t val;
        fread(&val, sizeof(int8_t), 1, pFile);
        return val;
    }

    uint8_t readUInt8(FILE* pFile)
    {
        uint8_t val;
        fread(&val, sizeof(uint8_t), 1, pFile);
        return val;
    }

    int16_t readInt16(FILE* pFile)
    {
        int16_t val;
        fread(&val, sizeof(int16_t), 1, pFile);
        return val;
    }

    uint16_t readUInt16(FILE* pFile)
    {
        uint16_t val;
        fread(&val, sizeof(uint16_t), 1, pFile);
        return val;
    }

    int32_t readInt32(FILE* pFile)
    {
        int32_t val;
        fread(&val, sizeof(int32_t), 1, pFile);
        return val;
    }

    uint32_t readUInt32(FILE* pFile)
    {
        uint32_t val;
        fread(&val, sizeof(uint32_t), 1, pFile);
        return val;
    }

    float readFloat(FILE* pFile)
    {
        float val;
        fread(&val, sizeof(float), 1, pFile);
        return val;
    }

    double readDouble(FILE* pFile)
    {
        double val;
        fread(&val, sizeof(double), 1, pFile);
        return val;
    }

    bool readBool(FILE* pFile)
    {
        uint8_t vali;
        fread(&vali, sizeof(uint8_t), 1, pFile);
        return vali ? true : false;
    }

    std::string readString(FILE* pFile)
    {
        std::string val;
        char c;
        do
        {
            auto readret = fread(&c, sizeof(c), 1, pFile);
            if (feof(pFile)) break;
            (void)readret;
            if (c) val += c;
        } while (c);
        return val;
    }

    void readFloat2(float* out, FILE* pFile)
    {
        fread(out, sizeof(float), 2, pFile);
    }

    void readFloat3(float* out, FILE* pFile)
    {
        fread(out, sizeof(float), 3, pFile);
    }

    void readFloat4(float* out, FILE* pFile)
    {
        fread(out, sizeof(float), 4, pFile);
    }

    void readInt2(int* out, FILE* pFile)
    {
        int32_t vals[2];
        fread(vals, sizeof(int32_t), 2, pFile);
        out[0] = (int)vals[0];
        out[1] = (int)vals[1];
    }

    void readInt4(int* out, FILE* pFile)
    {
        int32_t vals[4];
        fread(vals, sizeof(int32_t), 4, pFile);
        out[0] = (int)vals[0];
        out[1] = (int)vals[1];
        out[2] = (int)vals[2];
        out[3] = (int)vals[3];
    }

    void readMatrix(float* out, FILE* pFile)
    {
        fread(out, sizeof(float), 16, pFile);
    }

    uint32_t hash(const std::string& str, unsigned int seed)
    {
        //TODO: This is quite bad
        unsigned hash = seed;
        const char *s = str.c_str();
        while (*s) hash = hash * 101 + *s++;
        return hash;
    }

    std::string sha1(const std::string& str)
    {
        unsigned char resultHash[20] = {0};
        char hexstring[41];

        sha1::calc(str.c_str(), (int)str.size(), resultHash);
        sha1::toHexString(resultHash, hexstring);

        return hexstring;
    }

    std::string md5(const std::string& str)
    {
        char hash[33];
        md5::md5_t md5(str.c_str(), (const unsigned int)str.size());
        md5.get_string(hash);
        return hash;
    }

    bool validateEmail(const std::string& email)
    {
        return isValidEmailAddress(email.c_str());
    }

    std::string base64_encode(const uint8_t* buf, unsigned int bufLen)
    {
        std::string ret;
        int i = 0;
        int j = 0;
        uint8_t char_array_3[3];
        uint8_t char_array_4[4];

        while (bufLen--)
        {
            char_array_3[i++] = *(buf++);
            if (i == 3)
            {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; (i < 4); i++)
                    ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i)
        {
            for (j = i; j < 3; j++)
                char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (j = 0; (j < i + 1); j++)
                ret += base64_chars[char_array_4[j]];

            while ((i++ < 3))
                ret += '=';
        }

        return ret;
    }

    std::vector<uint8_t> base64_decode(const std::string& encoded_string)
    {
        int in_len = (int)encoded_string.size();
        int i = 0;
        int j = 0;
        int in_ = 0;
        uint8_t char_array_4[4], char_array_3[3];
        std::vector<uint8_t> ret;

        while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_]))
        {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i == 4)
            {
                for (i = 0; i < 4; i++)
                    char_array_4[i] = (uint8_t)base64_chars.find(char_array_4[i]);

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (i = 0; (i < 3); i++)
                    ret.push_back(char_array_3[i]);
                i = 0;
            }
        }

        if (i)
        {
            for (j = i; j < 4; j++)
                char_array_4[j] = 0;

            for (j = 0; j < 4; j++)
                char_array_4[j] = (uint8_t)base64_chars.find(char_array_4[j]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
        }

        return std::move(ret);
    }

    bool lerp(bool from, bool to, float t)
    {
        return (t < .5f) ? from : to;
    }

    int lerp(int from, int to, float t)
    {
        auto result = static_cast<float>(from)+(static_cast<float>(to)-static_cast<float>(from)) * t;
        return static_cast<int>(std::round(result));
    }

    unsigned int lerp(unsigned int from, unsigned int to, float t)
    {
        auto result = static_cast<float>(from)+(static_cast<float>(to)-static_cast<float>(from)) * t;
        result = std::round(result);
        if (result < 0.f) result = 0.f;
        return static_cast<unsigned int>(result);
    }

    float lerp(float from, float to, float t)
    {
        return from + (to - from) * t;
    }

    double lerp(double from, double to, float t)
    {
        return from + (to - from) * static_cast<double>(t);
    }

    std::string lerp(const std::string& from, const std::string& to, float t)
    {
        auto fromLen = from.size();
        auto toLen = to.size();
        auto newLen = static_cast<float>(fromLen)+(static_cast<float>(toLen)-static_cast<float>(fromLen)) * t;
        newLen = round(newLen);
        if (toLen > fromLen)
        {
            auto ret = to.substr(0, static_cast<size_t>(newLen));
            return std::move(ret);
        }
        else
        {
            auto ret = from.substr(0, static_cast<size_t>(newLen));
            return std::move(ret);
        }
    }

    void log(LogSeverity logSeverity, const std::string& message)
    {
        std::string output;
        switch (logSeverity)
        {
            case LogSeverity::Info:
                output = "(INFO): ";
                break;
            case LogSeverity::Warning:
                output = "(WARNING): ";
                break;
            case LogSeverity::Error:
                output = "(ERROR): ";
                break;
        }
        output += message + '\n';
#if defined(WIN32)
        OutputDebugStringA(output.c_str());
#else
        std::cout << output;
#endif
    }

    void logInfo(const std::string& message)
    {
        log(LogSeverity::Info, message);
    }

    void logWarning(const std::string& message)
    {
        log(LogSeverity::Warning, message);
    }

    void logError(const std::string& message)
    {
        log(LogSeverity::Error, message);
    }

    float tween(float t, Tween tween)
    {
        static const float SPRING_DIS = .3f;
        static const float INV_SPRING_DIS = .7f;

        switch (tween)
        {
            case Tween::None:
                return 0.f;
            case Tween::Linear:
                return t;
            case Tween::EaseIn:
                return t * t;
            case Tween::EaseOut:
            {
                auto inv = 1.f - t;
                return 1.f - inv * inv;
            }
            case Tween::EaseBoth:
            {
                if (t < .5f)
                {
                    return t * t * 2.f;
                }
                else
                {
                    auto clamped = (t - .5f) * 2.f;
                    auto inv = 1 - clamped;
                    clamped = 1 - inv * inv;
                    return clamped * .5f + .5f;
                }
                return 0.f;
            }
            case Tween::BounceIn:
            {
                auto inv = 1.f - t;
                float ret;
                if (inv < (1.f / 2.75f))
                {
                    ret = (7.5625f * inv * inv);
                }
                else if (inv < (2.f / 2.75f))
                {
                    auto postFix = inv - (1.5f / 2.75f);
                    ret = 7.5625f * postFix * postFix + .75f;
                }
                else if (inv < (2.5f / 2.7f))
                {
                    auto postFix = inv - (2.25f / 2.75f);
                    ret = 7.5625f * postFix * postFix + .9375f;
                }
                else
                {
                    auto postFix = inv - (2.625f / 2.75f);
                    ret = 7.5625f * postFix * postFix + .984375f;
                }
                return 1 - ret;
            }
            case Tween::BounceOut:
                if (t < (1.f / 2.75f))
                {
                    return (7.5625f * t * t);
                }
                else if (t < (2.f / 2.75f))
                {
                    auto postFix = t - (1.5f / 2.75f);
                    return (7.5625f * postFix * postFix + .75f);
                }
                else if (t < (2.5f / 2.75f))
                {
                    auto postFix = t - (2.25f / 2.75f);
                    return (7.5625f * postFix * postFix + .9375f);
                }
                else
                {
                    auto postFix = t - (2.625f / 2.75f);
                    return (7.5625f * postFix * postFix + .984375f);
                }
            case Tween::SpringIn:
            {
                float ret;
                if (t < SPRING_DIS)
                {
                    ret = t / SPRING_DIS;
                    ret = 1.f - (1.f - ret) * (1.f - ret);
                    ret = ret * -SPRING_DIS;
                }
                else
                {
                    ret = (t - SPRING_DIS) / INV_SPRING_DIS;
                    ret *= ret;
                    ret = ret * (1.f + SPRING_DIS) - SPRING_DIS;
                }
                return ret;
            }
            case Tween::SpringOut:
            {
                auto inv = 1.f - t;
                if (inv < SPRING_DIS)
                {
                    inv = inv / SPRING_DIS;
                    inv = 1.f - (1.f - inv) * (1.f - inv);
                    inv = inv * -SPRING_DIS;
                }
                else
                {
                    inv = (inv - SPRING_DIS) / INV_SPRING_DIS;
                    inv *= inv;
                    inv = inv * (1.f + SPRING_DIS) - SPRING_DIS;
                }
                return 1.f - inv;
            }
        }
        return t;
    }

    Tween invertTween(Tween tween)
    {
        switch (tween)
        {
            case Tween::None:
                return Tween::None;
            case Tween::Linear:
                return Tween::Linear;
            case Tween::EaseIn:
                return Tween::EaseOut;
            case Tween::EaseOut:
                return Tween::EaseIn;
            case Tween::EaseBoth:
                return Tween::EaseBoth;
            case Tween::BounceIn:
                return Tween::BounceOut;
            case Tween::BounceOut:
                return Tween::BounceIn;
            case Tween::SpringIn:
                return Tween::SpringOut;
            case Tween::SpringOut:
                return Tween::SpringIn;
        }
        return Tween::None;
    }

    bool loadJson(Json::Value &out, const std::string& filename)
    {
        std::ifstream file(filename);
        if (!file.is_open())
        {
            outils::logError("Failed to load file: " + filename);
            return false;
        }
        try
        {
            file >> out;
        }
        catch (...)
        {
            outils::logError("Failed to parse file: " + filename);
            file.close();
            return false;
        }
        file.close();
        return true;
    }

    bool saveJson(const Json::Value &json, const std::string& filename)
    {
        std::ofstream file(filename);
        if (!file.is_open())
        {
            outils::logError("Failed to save file: " + filename);
            return false;
        }

        Json::StyledWriter styledWriter;

        auto str = styledWriter.write(json);
        file << str;
        file.close();

        return true;
    }


    Json::Value serializeInt8(int8_t val)
    {
        return val;
    }

    Json::Value serializeUInt8(uint8_t val)
    {
        return val;
    }

    Json::Value serializeInt16(int16_t val)
    {
        return val;
    }

    Json::Value serializeUInt16(uint16_t val)
    {
        return val;
    }

    Json::Value serializeInt32(int32_t val)
    {
        return val;
    }

    Json::Value serializeUInt32(uint32_t val)
    {
        return val;
    }

    Json::Value serializeInt64(int64_t val)
    {
        return val;
    }

    Json::Value serializeUInt64(uint64_t val)
    {
        return val;
    }

    Json::Value serializeFloat(float val)
    {
        return val;
    }

    Json::Value serializeDouble(double val)
    {
        return val;
    }

    Json::Value serializeBool(bool val)
    {
        return val;
    }

    Json::Value serializeString(const std::string &val)
    {
        return val;
    }

    Json::Value serializeFloat2(const float *val)
    {
        Json::Value ret(Json::arrayValue);
        ret.append(val[0]);
        ret.append(val[1]);
        return ret;
    }

    Json::Value serializeFloat3(const float *val)
    {
        Json::Value ret(Json::arrayValue);
        ret.append(val[0]);
        ret.append(val[1]);
        ret.append(val[2]);
        return ret;
    }

    Json::Value serializeFloat4(const float *val)
    {
        Json::Value ret(Json::arrayValue);
        ret.append(val[0]);
        ret.append(val[1]);
        ret.append(val[2]);
        ret.append(val[3]);
        return ret;
    }

    Json::Value serializeInt2(const int *val)
    {
        Json::Value ret(Json::arrayValue);
        ret.append(val[0]);
        ret.append(val[1]);
        return ret;
    }

    Json::Value serializeInt4(const int *val)
    {
        Json::Value ret(Json::arrayValue);
        ret.append(val[0]);
        ret.append(val[1]);
        ret.append(val[2]);
        ret.append(val[3]);
        return ret;
    }

    Json::Value serializeMatrix(const float *val)
    {
        Json::Value ret(Json::arrayValue);
        for (int i = 0; i < 16; ++i)
            ret.append(val[i]);
        return ret;
    }

    Json::Value serializeStringArray(const std::vector<std::string> &val)
    {
        Json::Value ret(Json::arrayValue);
        for (const auto &str : val)
            ret.append(str);
        return ret;
    }

    int8_t deserializeInt8(const Json::Value &json, int8_t in_default)
    {
        if (!json.isInt()) return in_default;
        return (int8_t)json.asInt();
    }

    uint8_t deserializeUInt8(const Json::Value &json, uint8_t in_default)
    {
        if (!json.isUInt()) return in_default;
        return (uint8_t)json.asUInt();
    }

    int16_t deserializeInt16(const Json::Value &json, int16_t in_default)
    {
        if (!json.isInt()) return in_default;
        return (int16_t)json.asInt();
    }

    uint16_t deserializeUInt16(const Json::Value &json, uint16_t in_default)
    {
        if (!json.isUInt()) return in_default;
        return (uint16_t)json.asUInt();
    }

    int32_t deserializeInt32(const Json::Value &json, int32_t in_default)
    {
        if (!json.isInt()) return in_default;
        return (int32_t)json.asInt();
    }

    uint32_t deserializeUInt32(const Json::Value &json, uint32_t in_default)
    {
        if (!json.isUInt()) return in_default;
        return (uint32_t)json.asUInt();
    }

    int64_t deserializeInt64(const Json::Value &json, int64_t in_default)
    {
        if (!json.isInt64()) return in_default;
        return (int64_t)json.asInt64();
    }

    uint64_t deserializeUInt64(const Json::Value &json, uint64_t in_default)
    {
        if (!json.isUInt64()) return in_default;
        return (uint64_t)json.asUInt64();
    }

    float deserializeFloat(const Json::Value &json, float in_default)
    {
        if (!json.isDouble()) return in_default;
        return json.asFloat();
    }

    double deserializeDouble(const Json::Value &json, double in_default)
    {
        if (!json.isDouble()) return in_default;
        return json.asDouble();
    }

    bool deserializeBool(const Json::Value &json, bool in_default)
    {
        if (!json.isBool()) return in_default;
        return json.asBool();
    }

    std::string deserializeString(const Json::Value &json, const std::string &in_default)
    {
        if (!json.isString()) return in_default;
        return json.asString();
    }

    static const float DEFAULT_FLOATS[4]  = {0, 0, 0, 0};
    static const int   DEFAULT_INTS[4]    = {0, 0, 0, 0};
    static const float DEFAULT_MATRIX[16] = {1, 0, 0, 0,
                                             0, 1, 0, 0,
                                             0, 0, 1, 0,
                                             0, 0, 0, 1};

    void deserializeFloat2(float* out, const Json::Value &json, const float *in_default)
    {
        if (in_default == nullptr) in_default = DEFAULT_FLOATS;
        if (!json.isArray() || json.size() != 2)
        {
            memcpy(out, in_default, sizeof(float) * 2);
            return;
        }
        for (int i = 0; i < 2; ++i)
        {
            if (!json[i].isDouble())
            {
                memcpy(out, in_default, sizeof(float) * 2);
                return;
            }
            out[i] = json[i].asFloat();
        }
    }

    void deserializeFloat3(float* out, const Json::Value &json, const float *in_default)
    {
        if (in_default == nullptr) in_default = DEFAULT_FLOATS;
        if (!json.isArray() || json.size() != 3)
        {
            memcpy(out, in_default, sizeof(float) * 3);
            return;
        }
        for (int i = 0; i < 3; ++i)
        {
            if (!json[i].isDouble())
            {
                memcpy(out, in_default, sizeof(float) * 3);
                return;
            }
            out[i] = json[i].asFloat();
        }
    }

    void deserializeFloat4(float* out, const Json::Value &json, const float *in_default)
    {
        if (in_default == nullptr) in_default = DEFAULT_FLOATS;
        if (!json.isArray() || json.size() != 4)
        {
            memcpy(out, in_default, sizeof(float) * 4);
            return;
        }
        for (int i = 0; i < 4; ++i)
        {
            if (!json[i].isDouble())
            {
                memcpy(out, in_default, sizeof(float) * 4);
                return;
            }
            out[i] = json[i].asFloat();
        }
    }

    void deserializeInt2(int* out, const Json::Value &json, const int *in_default)
    {
        if (in_default == nullptr) in_default = DEFAULT_INTS;
        if (!json.isArray() || json.size() != 2)
        {
            memcpy(out, in_default, sizeof(int) * 2);
            return;
        }
        for (int i = 0; i < 2; ++i)
        {
            if (!json[i].isInt())
            {
                memcpy(out, in_default, sizeof(int) * 2);
                return;
            }
            out[i] = (int)json[i].asInt();
        }
    }

    void deserializeInt4(int* out, const Json::Value &json, const int *in_default)
    {
        if (in_default == nullptr) in_default = DEFAULT_INTS;
        if (!json.isArray() || json.size() != 4)
        {
            memcpy(out, in_default, sizeof(int) * 4);
            return;
        }
        for (int i = 0; i < 4; ++i)
        {
            if (!json[i].isInt())
            {
                memcpy(out, in_default, sizeof(float) * 4);
                return;
            }
            out[i] = (int)json[i].asInt();
        }
    }

    void deserializeMatrix(float* out, const Json::Value &json, const float *in_default)
    {
        if (in_default == nullptr) in_default = DEFAULT_MATRIX;
        if (!json.isArray() || json.size() != 16)
        {
            memcpy(out, in_default, sizeof(float) * 16);
            return;
        }
        for (int i = 0; i < 16; ++i)
        {
            if (!json[i].isDouble())
            {
                memcpy(out, in_default, sizeof(float) * 16);
                return;
            }
            out[i] = json[i].asFloat();
        }
    }

    std::vector<std::string> deserializeStringArray(const Json::Value &json, const std::vector<std::string> &in_default)
    {
        if (!json.isArray())
        {
            return in_default;
        }
        std::vector<std::string> ret;
        for (const auto &valJson : json)
        {
            if (valJson.isString())
            {
                ret.push_back(valJson.asString());
            }
            else
            {
                ret.push_back("");
            }
        }
        return ret;
    }
}
