//
//  cevfs.h
//  sqlite
//
//  Created by Ryan Homer on 5/2/2016.
//  Copyright © 2016 Murage Inc. All rights reserved.
//

#ifndef cevfs_h
#define cevfs_h

#define CEVFS_ERROR                              111
#define CEVFS_ERROR_PAGE_SIZE_TOO_SMALL          (CEVFS_ERROR | (1<<8))
#define CEVFS_ERROR_MALFORMED_KEY                (CEVFS_ERROR | (2<<8))
#define CEVFS_ERROR_EXT_VERSION_TOO_OLD          (CEVFS_ERROR | (3<<8))
#define CEVFS_ERROR_ALREADY_REGISTERED           (CEVFS_ERROR | (4<<8))

int cevfs_register(
  const char *zName,                /* Name of the newly constructed VFS */
  const char *zParent,              /* Name of the underlying VFS. NULL to use default. */
  void *pCtx,                       /* Context pointer to be passed to compress functions */
  int (*xCompressBound)(void *pCtx, int nSrc),
  int (*xCompress)(void *pCtx, char *aDest, int *pnDest, char *aSrc, int nSrc),
  int (*xUncompress)(void *pCtx, char *aDest, int *pnDest, char *aSrc, int nSrc)
);

int cevfs_set_vfs_key(const char *zName, const char *pExpr);
int cevfs_unregister(const char *zName);

// Use these for compression/decompression if you don't want to add your own
int cevfsDefaultCompressBound(void *p, int nByte);
int cevfsDefaultCompress(void *p, char *aDest, int *pnDest, char *aSrc, int nSrc);
int cevfsDefaultUncompress(void *p, char *aDest, int *pnDest, char *aSrc, int nSrc);

/*!
 \brief Create new compresses/encrypted database from existing database.
 \param srcDbPath Standard path to existing uncompressed, unencrypted SQLite database file.
 \param destUri URI of non-existing destination database file with optional parameters (block_size, key)
 */
int cevfs_build(const char *srcDbPath, const char *destUri);

#endif /* cevfs_h */
