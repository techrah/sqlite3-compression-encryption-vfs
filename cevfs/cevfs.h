//
//  cevfs.h
//  sqlite
//
//  Created by Ryan Homer on 5/2/2016.
//  Copyright © 2016 Murage Inc. All rights reserved.
//

#ifndef cevfs_h
#define cevfs_h

#define CEVFS_OK                                 0

#define CEVFS_ERROR                              111
#define CEVFS_ERROR_PAGE_SIZE_TOO_SMALL          (CEVFS_ERROR | (1<<8))
#define CEVFS_ERROR_MALFORMED_KEY                (CEVFS_ERROR | (2<<8))
#define CEVFS_ERROR_EXT_VERSION_TOO_OLD          (CEVFS_ERROR | (3<<8))
#define CEVFS_ERROR_VFS_ALREADY_EXISTS           (CEVFS_ERROR | (4<<8))
#define CEVFS_ERROR_COMPRESSION_FAILED           (CEVFS_ERROR | (5<<8))
#define CEVFS_ERROR_DECOMPRESSION_FAILED         (CEVFS_ERROR | (6<<8))
#define CEVFS_ERROR_ENCRYPTION_FAILED            (CEVFS_ERROR | (7<<8))
#define CEVFS_ERROR_DECRYPTION_FAILED            (CEVFS_ERROR | (8<<8))

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

typedef int (*t_xAutoDetect)(void *pCtx, const char *zFile, const char *zHdr, size_t *pEncIvSz, CevfsMethods*);

int cevfs_create_vfs(
  char const *zName,     // Name of the newly constructed VFS.
  char const *zParent,   // Name of the underlying VFS. NULL to use default.
  void *pCtx,            // Context pointer to be passed to CEVFS methods.
  t_xAutoDetect
);

int cevfs_set_vfs_key(const char *zName, const char *pExpr);
int cevfs_destroy_vfs(const char *zName);

/*!
 \brief Create new compresses/encrypted database from existing database.
 \param srcDbPath Standard path to existing uncompressed, unencrypted SQLite database file.
 \param destUri URI of non-existing destination database file with optional parameters (block_size, key)
 */
int cevfs_build(
  const char *zSrcFilename,  // Source SQLite DB filename, including path. Can be a URI.
  const char *zDestFilename, // Destination SQLite DB filename, including path. Can be a URI.
  void *pCtx,                // Context pointer to be passed to CEVFS xMethods.
  t_xAutoDetect              // xAutoDetect method to set up xMethods.
);

#endif /* cevfs_h */
