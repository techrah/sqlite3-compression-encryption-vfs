/**
CEVFS
Compression & Encryption VFS

Copyright (c) 2016 Ryan Homer, Murage Inc.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef __CEVFS_H__
#define __CEVFS_H__

#define CEVFS_OK                                 0

#define CEVFS_ERROR                              111
#define CEVFS_ERROR_PAGE_SIZE_TOO_SMALL          (CEVFS_ERROR | (1<<8))
#define CEVFS_ERROR_MALFORMED_KEY                (CEVFS_ERROR | (2<<8))
#define CEVFS_ERROR_EXT_VERSION_TOO_OLD          (CEVFS_ERROR | (3<<8))
#define CEVFS_ERROR_VFS_ALREADY_EXISTS           (CEVFS_ERROR | (4<<8))
#define CEVFS_ERROR_VFS_DOES_NOT_EXIST           (CEVFS_ERROR | (5<<8))
#define CEVFS_ERROR_COMPRESSION_FAILED           (CEVFS_ERROR | (6<<8))
#define CEVFS_ERROR_DECOMPRESSION_FAILED         (CEVFS_ERROR | (7<<8))
#define CEVFS_ERROR_ENCRYPTION_FAILED            (CEVFS_ERROR | (8<<8))
#define CEVFS_ERROR_DECRYPTION_FAILED            (CEVFS_ERROR | (9<<8))

struct CevfsMethods {
  void *pCtx;

  int (*xCompressBound)(void *pCtx, size_t nDataInSize);
  int (*xCompress)  (void *pCtx, char *aDest, size_t *pnDataOutSize, char *aSrc, size_t nDataInSize);
  int (*xUncompress)(void *pCtx, char *aDest, size_t *pnDataOutSize, char *aSrc, size_t nDataInSize);

  int (*xEncrypt)(
    void *pCtx,                  // in:  the context
    const void *pDataIn,         // in:  the unencrypted data
    size_t nDataInSize,          // in:  the size of the unencrypted data
    void *pIvOut,                // out: the randomly created IV
    void **pDataOut,             // out: the encrypted data
    size_t *nDataSizeOut,        // out: size of encrypted data
    void *sqlite3_malloc(int n)  // in:  pointer to the sqlite3_malloc function
  );

  int (*xDecrypt)(
    void *pCtx,
    const void *pDataIn,
    size_t nDataInSize,
    const void *pIvIn,
    void *pDataOut,
    size_t nDataBufferSizeOut,
    size_t *nDataSizeOut
  );
};
typedef struct CevfsMethods CevfsMethods;

typedef int (*t_xAutoDetect)(
  void *pCtx,            // Pointer to context passed in via 3rd param of cevfs_create_vfs.
  const char *zFile,     // Pointer to buffer containing the database filename.
  const char *zHdr,      // NULL if new database, otherwise database header after CEVFS- prefix.
  size_t *pEncIvSz,      // Pointer to encryption initialization vector (IV) size.
  CevfsMethods*);        // Pointer to compression/encryption methods.

int cevfs_create_vfs(
  char const *zName,     // Name of the newly constructed VFS.
  char const *zParent,   // Name of the underlying VFS. NULL to use default.
  void *pCtx,            // Context pointer to be passed to CEVFS methods.
  t_xAutoDetect,         // xAutoDetect method to set up xMethods.
  int makeDefault        // BOOL: Make this the default VFS? Typically false.
);

int cevfs_destroy_vfs(const char *zName);

/*!
 \brief Create new compresses/encrypted database from existing database.
 \param zSrcFilename Standard path to existing uncompressed, unencrypted SQLite database file.
 \param zDestFilename URI of non-existing destination database file with optional parameters (block_size, key)
 */
int cevfs_build(
  const char *zSrcFilename,  // Source SQLite DB filename, including path. Can be a URI.
  const char *zDestFilename, // Destination SQLite DB filename, including path. Can be a URI.
  const char *vfsName,       // This will be embedded into the header of the database file.
  void *pCtx,                // Context pointer to be passed to CEVFS xMethods.
  t_xAutoDetect              // xAutoDetect method to set up xMethods.
);

#endif /* __CEVFS_H__ */
