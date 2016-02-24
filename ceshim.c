/*
 Compression & Encryption Shim VFS
*/
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"
#include "sqliteInt.h"
#include "pager.h"
#include "btreeInt.h"

// First 100 bytes for pager, second 100 bytes for pagemap and other data
#define CESHIM_DB_HEADER_PGR_SZ     100
#define CESHIM_DB_HEADER_MAP_SZ     100
#define CESHIM_DB_HEADER_SIZE       (CESHIM_DB_HEADER_PGR_SZ + CESHIM_DB_HEADER_MAP_SZ)

// Each page holds many compressed pages and has a page map header
#define CESHIM_PAGE_HEADER_SIZE     100
#define CESHIM_MAX_PAGE_MAP_ENTRIES  10
#define CESHIM_MAX_OFFSET_ENTRIES    10

typedef u16 CeshimCompressedSize;
typedef u16 CeshimCompressedOffset;

/*
 ** The header string that appears at the beginning of every
 ** SQLite database.
 */
static const char zMagicHeader[] = SQLITE_FILE_HEADER;

/*
** Keeps track of uncompress to compressed pager page mappings.
** In memory during writing. Needs to be persisted when db is closed.
*/
typedef struct ceshim_pagemap_entry ceshim_pagemap_entry;
struct __attribute__ ((__packed__)) ceshim_pagemap_entry {
  Pgno uppPgno;
  Pgno lwrPgno;
};
typedef struct ceshim_pagemap ceshim_pagemap;
struct __attribute__ ((__packed__)) ceshim_pagemap {
  u8 nCount;                            // 01 number of pagemap entries in use
  Pgno currPgno;                        // 04 curr lower pager pgno being filled
  Pgno uppPageFile;                     // 04 max pgno in upper pager, used to report filesize
  Pgno lwrPageFile;                     // 04 max pgno in lower pager, used to update pager header
  CeshimCompressedOffset currPageOfst;  // 02 curr offset for next compressed page
  unsigned char reserved[5];            // 05 pad structure to 100 bytes
  ceshim_pagemap_entry entries[10];     // 80 page mappings
};

/*
** Each page will have header for mapping source offset to correct compressed sub-page.
** Each entry will be a pair of source offset (u64) and size of compressed page (u16).
** Therefore the header size is (8 bytes + 2 bytes) * 10 entries = 100 bytes.
*/
typedef struct ceshim_offset_entry ceshim_offset_entry;
struct __attribute__ ((__packed__)) ceshim_offset_entry {
  sqlite3_uint64 offset;               /* 08 Offset from read request for top-level pager */
  CeshimCompressedSize pageSize;       /* 02 Size of compressed page */
};
typedef struct CeshimMemPage CeshimMemPage;
struct CeshimMemPage {
  DbPage *pDbPage;                     /* Pager page handle */
  Pgno pgno;                           /* The pgno to which this belongs */
  u8 dbHdrOffset;                      /* Offset to the beginning of the header */
  u8 pgHdrOffset;                      /* Offset to the beginning of the data */
  u8 *aData;                           /* Pointer to disk image of the page data */
  ceshim_offset_entry *offsetEntries;
};

/*
** An instance of this structure is attached to the each trace VFS to
** provide auxiliary information.
*/
typedef struct ceshim_info ceshim_info;
struct ceshim_info {
  sqlite3_vfs *pRootVfs;              /* The underlying real VFS */

  int (*xCompressBound)(void *, int nSrc);
  int (*xCompress)(void *, char *aDest, int *pnDest, char *aSrc, int nSrc);
  int (*xUncompress)(void *, char *aDest, int *pnDest, char *aSrc, int nSrc);

  // Trace Output
  int (*xOut)(const char*, void*);    /* Send output here */
  void *pOutArg;                      /* First argument to xOut */

  const char *zVfsName;               /* Name of this VFS */
  char *zUppJournalPath;              /* Path to redirect upper journal */
  sqlite3_vfs *pCeshimVfs;            /* Pointer back to the ceshim VFS */
  ceshim_pagemap pagemap;             /* Page mapping data */
  CeshimMemPage *pPage1;              /* Page 1 of the pager */
};

/*
** The sqlite3_file object for the shim.
*/
typedef struct ceshim_file ceshim_file;
struct ceshim_file {
  sqlite3_file base;                /* Base class.  Must be first */
  ceshim_info *pInfo;               /* Custom info for this file */
  const char *zFName;               /* Base name of the file */
  sqlite3_file *pReal;              /* The real underlying file */

  Pager *pPager;                    /* Pager for I/O with compressed/encrypted file */
  u32 pageSize;
  u32 usableSize;                   /* Number of usable bytes on each page */
  u8 nTransactions;                 /* Number of open transactions on the pager */
};

/*
** Method declarations for ceshim_file.
*/
static int ceshimClose(sqlite3_file*);
static int ceshimRead(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
static int ceshimWrite(sqlite3_file*,const void*,int iAmt, sqlite3_int64);
static int ceshimTruncate(sqlite3_file*, sqlite3_int64 size);
static int ceshimSync(sqlite3_file*, int flags);
static int ceshimFileSize(sqlite3_file*, sqlite3_int64 *pSize);
static int ceshimLock(sqlite3_file*, int);
static int ceshimUnlock(sqlite3_file*, int);
static int ceshimCheckReservedLock(sqlite3_file*, int *);
static int ceshimFileControl(sqlite3_file*, int op, void *pArg);
static int ceshimSectorSize(sqlite3_file*);
static int ceshimDeviceCharacteristics(sqlite3_file*);
static int ceshimShmLock(sqlite3_file*,int,int,int);
static int ceshimShmMap(sqlite3_file*,int,int,int, void volatile **);
static void ceshimShmBarrier(sqlite3_file*);
static int ceshimShmUnmap(sqlite3_file*,int);

/*
** Method declarations for ceshim_vfs.
*/
static int ceshimOpen(sqlite3_vfs*, const char *, sqlite3_file*, int , int *);
static int ceshimDelete(sqlite3_vfs*, const char *zName, int syncDir);
static int ceshimAccess(sqlite3_vfs*, const char *zName, int flags, int *);
static int ceshimFullPathname(sqlite3_vfs*, const char *zName, int, char *);
static void *ceshimDlOpen(sqlite3_vfs*, const char *zFilename);
static void ceshimDlError(sqlite3_vfs*, int nByte, char *zErrMsg);
static void (*ceshimDlSym(sqlite3_vfs*,void*, const char *zSymbol))(void);
static void ceshimDlClose(sqlite3_vfs*, void*);
static int ceshimRandomness(sqlite3_vfs*, int nByte, char *zOut);
static int ceshimSleep(sqlite3_vfs*, int microseconds);
static int ceshimCurrentTime(sqlite3_vfs*, double*);
static int ceshimGetLastError(sqlite3_vfs*, int, char*);
static int ceshimCurrentTimeInt64(sqlite3_vfs*, sqlite3_int64*);
static int ceshimSetSystemCall(sqlite3_vfs*,const char*, sqlite3_syscall_ptr);
static sqlite3_syscall_ptr ceshimGetSystemCall(sqlite3_vfs*, const char *);
static const char *ceshimNextSystemCall(sqlite3_vfs*, const char *zName);

/*
** Return a pointer to the tail of the pathname.  Examples:
**
**     /home/drh/xyzzy.txt -> xyzzy.txt
**     xyzzy.txt           -> xyzzy.txt
*/
static const char *fileTail(const char *z){
  int i;
  if( z==0 ) return 0;
  i = (int)strlen(z)-1;
  while( i>0 && z[i-1]!='/' ){ i--; }
  return &z[i];
}

/*
** Send trace output defined by zFormat and subsequent arguments.
*/
static void ceshim_printf(
  ceshim_info *pInfo,
  const char *zFormat,
  ...
){
  va_list ap;
  char *zMsg;
  va_start(ap, zFormat);
  zMsg = sqlite3_vmprintf(zFormat, ap);
  va_end(ap);
  pInfo->xOut(zMsg, pInfo->pOutArg);
  sqlite3_free(zMsg);
}

/*
** Convert value rc into a string and print it using zFormat.  zFormat
** should have exactly one %s
*/
static void ceshim_print_errcode(
  ceshim_info *pInfo,
  const char *zFormat,
  int rc
){
  char zBuf[50];
  char *zVal;
  switch( rc ){
    case SQLITE_OK:         zVal = "SQLITE_OK";          break;
    case SQLITE_ERROR:      zVal = "SQLITE_ERROR";       break;
    case SQLITE_PERM:       zVal = "SQLITE_PERM";        break;
    case SQLITE_ABORT:      zVal = "SQLITE_ABORT";       break;
    case SQLITE_BUSY:       zVal = "SQLITE_BUSY";        break;
    case SQLITE_NOMEM:      zVal = "SQLITE_NOMEM";       break;
    case SQLITE_READONLY:   zVal = "SQLITE_READONLY";    break;
    case SQLITE_INTERRUPT:  zVal = "SQLITE_INTERRUPT";   break;
    case SQLITE_IOERR:      zVal = "SQLITE_IOERR";       break;
    case SQLITE_CORRUPT:    zVal = "SQLITE_CORRUPT";     break;
    case SQLITE_FULL:       zVal = "SQLITE_FULL";        break;
    case SQLITE_CANTOPEN:   zVal = "SQLITE_CANTOPEN";    break;
    case SQLITE_PROTOCOL:   zVal = "SQLITE_PROTOCOL";    break;
    case SQLITE_EMPTY:      zVal = "SQLITE_EMPTY";       break;
    case SQLITE_SCHEMA:     zVal = "SQLITE_SCHEMA";      break;
    case SQLITE_CONSTRAINT: zVal = "SQLITE_CONSTRAINT";  break;
    case SQLITE_MISMATCH:   zVal = "SQLITE_MISMATCH";    break;
    case SQLITE_MISUSE:     zVal = "SQLITE_MISUSE";      break;
    case SQLITE_NOLFS:      zVal = "SQLITE_NOLFS";       break;
    case SQLITE_IOERR_READ:         zVal = "SQLITE_IOERR_READ";         break;
    case SQLITE_IOERR_SHORT_READ:   zVal = "SQLITE_IOERR_SHORT_READ";   break;
    case SQLITE_IOERR_WRITE:        zVal = "SQLITE_IOERR_WRITE";        break;
    case SQLITE_IOERR_FSYNC:        zVal = "SQLITE_IOERR_FSYNC";        break;
    case SQLITE_IOERR_DIR_FSYNC:    zVal = "SQLITE_IOERR_DIR_FSYNC";    break;
    case SQLITE_IOERR_TRUNCATE:     zVal = "SQLITE_IOERR_TRUNCATE";     break;
    case SQLITE_IOERR_FSTAT:        zVal = "SQLITE_IOERR_FSTAT";        break;
    case SQLITE_IOERR_UNLOCK:       zVal = "SQLITE_IOERR_UNLOCK";       break;
    case SQLITE_IOERR_RDLOCK:       zVal = "SQLITE_IOERR_RDLOCK";       break;
    case SQLITE_IOERR_DELETE:       zVal = "SQLITE_IOERR_DELETE";       break;
    case SQLITE_IOERR_BLOCKED:      zVal = "SQLITE_IOERR_BLOCKED";      break;
    case SQLITE_IOERR_NOMEM:        zVal = "SQLITE_IOERR_NOMEM";        break;
    case SQLITE_IOERR_ACCESS:       zVal = "SQLITE_IOERR_ACCESS";       break;
    case SQLITE_IOERR_CHECKRESERVEDLOCK:
                               zVal = "SQLITE_IOERR_CHECKRESERVEDLOCK"; break;
    case SQLITE_IOERR_LOCK:         zVal = "SQLITE_IOERR_LOCK";         break;
    case SQLITE_IOERR_CLOSE:        zVal = "SQLITE_IOERR_CLOSE";        break;
    case SQLITE_IOERR_DIR_CLOSE:    zVal = "SQLITE_IOERR_DIR_CLOSE";    break;
    case SQLITE_IOERR_SHMOPEN:      zVal = "SQLITE_IOERR_SHMOPEN";      break;
    case SQLITE_IOERR_SHMSIZE:      zVal = "SQLITE_IOERR_SHMSIZE";      break;
    case SQLITE_IOERR_SHMLOCK:      zVal = "SQLITE_IOERR_SHMLOCK";      break;
    case SQLITE_IOERR_SHMMAP:       zVal = "SQLITE_IOERR_SHMMAP";       break;
    case SQLITE_IOERR_SEEK:         zVal = "SQLITE_IOERR_SEEK";         break;
    case SQLITE_IOERR_GETTEMPPATH:  zVal = "SQLITE_IOERR_GETTEMPPATH";  break;
    case SQLITE_IOERR_CONVPATH:     zVal = "SQLITE_IOERR_CONVPATH";     break;
    case SQLITE_READONLY_DBMOVED:   zVal = "SQLITE_READONLY_DBMOVED";   break;
    case SQLITE_LOCKED_SHAREDCACHE: zVal = "SQLITE_LOCKED_SHAREDCACHE"; break;
    case SQLITE_BUSY_RECOVERY:      zVal = "SQLITE_BUSY_RECOVERY";      break;
    case SQLITE_CANTOPEN_NOTEMPDIR: zVal = "SQLITE_CANTOPEN_NOTEMPDIR"; break;
    default: {
       sqlite3_snprintf(sizeof(zBuf), zBuf, "%d", rc);
       zVal = zBuf;
       break;
    }
  }
  ceshim_printf(pInfo, zFormat, zVal);
}

/*
** Append to a buffer.
*/
static void strappend(char *z, int *pI, const char *zAppend){
  int i = *pI;
  while( zAppend[0] ){ z[i++] = *(zAppend++); }
  z[i] = 0;
  *pI = i;
}

static int ceshimReadUncompressed(
  Pager *pPager,
  Pgno pgno,
  CeshimCompressedOffset offset,
  void *zBuf,
  int iAmt
){
  int rc;
  DbPage *pPage;
  if( (rc = sqlite3PagerGet(pPager, pgno, &pPage, 0)) == SQLITE_OK ){
    void *data = sqlite3PagerGetData(pPage);
    memcpy(zBuf, data+offset, iAmt);
    sqlite3PagerUnref(pPage);
  }
  return rc;
}

static int ceshimPagerGet(
  ceshim_file *pFile,
  Pgno pgno,          /* Page number to fetch */
  DbPage **ppPage,    /* Write a pointer to the page here */
  int flags           /* PAGER_GET_XXX flags */
);

static int ceshimPagerWrite(ceshim_file *p, PgHdr *pPg){
int rc = SQLITE_OK;
  if( p->nTransactions == 0 ){
    if( (rc = sqlite3PagerBegin(p->pPager, 0, 1))==SQLITE_OK ){
      p->nTransactions++;
    }
  }
  if( rc==SQLITE_OK ) return sqlite3PagerWrite(pPg);
  return rc;
}

static int ceshimWriteUncompressed(
  ceshim_file *pFile,
  Pgno pgno,
  CeshimCompressedOffset offset,
  const void *zBuf,
  int iAmt
){
  int rc;
  DbPage *pPage;
  if( (rc = ceshimPagerGet(pFile, pgno, &pPage, 0)) == SQLITE_OK ){
    void *data = sqlite3PagerGetData(pPage);
    if( (rc = ceshimPagerWrite(pFile, pPage)) == SQLITE_OK ){
      memcpy(data+offset, zBuf, iAmt);
    }
    sqlite3PagerUnref(pPage);
  }
  return rc;
}

static CeshimMemPage *memPageFromDbPage(DbPage *pDbPage, Pgno mappedPgno){
  CeshimMemPage* pPg = (CeshimMemPage *)sqlite3PagerGetExtra(pDbPage);
  if(mappedPgno != pPg->pgno  ){
    pPg->pgno = mappedPgno;
    pPg->pDbPage = pDbPage;
    pPg->dbHdrOffset = mappedPgno==1 ? CESHIM_DB_HEADER_SIZE : 0;
    pPg->pgHdrOffset = CESHIM_PAGE_HEADER_SIZE; //sizeof(ceshim_offset_entry) * CESHIM_MAX_OFFSET_ENTRIES;
    pPg->pDbPage->pgno = mappedPgno; // pager uses this to determine pager size
    pPg->offsetEntries = sqlite3_malloc(pPg->pgHdrOffset); /* TODO: FREE */
    pPg->aData = sqlite3PagerGetData(pDbPage);

    // restore compressed pages offset data
    ceshimReadUncompressed(pDbPage->pPager, mappedPgno, pPg->dbHdrOffset, pPg->offsetEntries, pPg->pgHdrOffset);
    // restored nothing? init new table
    if( pPg->offsetEntries[0].offset == 0 && pPg->offsetEntries[0].pageSize == 0 )
      memset(pPg->offsetEntries, 0xFF, pPg->pgHdrOffset); /* offset 0xFFFFFFFFFFFFFFFF means not in use. 0 is a valid offset. */
  }
  return pPg;
}

static int ceshimNewDatabase(ceshim_file *pFile){
  CeshimMemPage *pP1;
  unsigned char *data;
  int rc;
  ceshim_info *pInfo = pFile->pInfo;

  pP1 = pInfo->pPage1;
  data = pP1->aData;
  if( (rc = ceshimPagerWrite(pFile, pP1->pDbPage))==SQLITE_OK ){
    // since we are using a secondary pager, set up a proper pager header (see btree.c:1898)
    memcpy(data, zMagicHeader, sizeof(zMagicHeader));
    assert( sizeof(zMagicHeader)==16 );
    data[16] = (u8)((pFile->pageSize>>8)&0xff);
    data[17] = (u8)((pFile->pageSize>>16)&0xff);
    data[18] = 1;
    data[19] = 1;
    assert( pFile->usableSize<=pFile->pageSize && pFile->usableSize+255>=pFile->pageSize);
    data[20] = (u8)(pFile->pageSize - pFile->usableSize);
    data[21] = 64;
    data[22] = 32;
    data[23] = 32;
    memset(&data[24], 0, 100-24);
    data[31] = 1; // 28-31 size of the database file in pages
  }
  return rc;
}

static CeshimCompressedOffset ceshimGetPageOffset(
  const ceshim_file *p,
  const CeshimMemPage *pMemPage,
  sqlite_uint64 uSrcOfst,
  CeshimCompressedSize *sz
){
  assert( pMemPage );
  assert( pMemPage->offsetEntries );

  // offset of beginning of compressed page, starting after all headers
  CeshimCompressedOffset ofst = 0;
  if ( sz ) *sz = 0;

  CeshimCompressedOffset prev = 0;
  for(u8 i=0; i<CESHIM_MAX_OFFSET_ENTRIES; i++){
    if( pMemPage->offsetEntries[i].offset <= uSrcOfst ) {
      ofst += prev;
      prev = pMemPage->offsetEntries[i].pageSize;
      if( sz ){
        *sz = pMemPage->offsetEntries[i].pageSize;
      }
    } else break;
  }
  return ofst;
}

static int ceshimSetPageOffset(
  const CeshimMemPage *pMemPage,
  ceshim_file *pFile,
  sqlite_int64 iSrcOfst,
  CeshimCompressedSize size
){
  assert( pMemPage );
  int rc = SQLITE_OK;
  // if already exists, update size & offset
  for(u8 i=0; i<CESHIM_MAX_OFFSET_ENTRIES; i++){
    if( pMemPage->offsetEntries[i].offset == iSrcOfst ) {
      if( pMemPage->offsetEntries[i].pageSize < size ) {
        CeshimCompressedOffset delta = size - pMemPage->offsetEntries[i].pageSize;
        pMemPage->offsetEntries[i].pageSize = size; // update size
        ceshim_info *pInfo = pFile->pInfo;
        ceshim_pagemap *pagemap = &pInfo->pagemap;
        pagemap->currPageOfst += delta; // update offset
      }
      return rc;
    }
  }
  // else add new entry to offset map
  u8 i=0;
  for(; i<CESHIM_MAX_OFFSET_ENTRIES; i++){
    if( pMemPage->offsetEntries[i].offset == 0xFFFFFFFFFFFFFFFF ){
      pMemPage->offsetEntries[i].offset = iSrcOfst;
      pMemPage->offsetEntries[i].pageSize = size;
      rc = ceshimWriteUncompressed(
        pFile,
        pMemPage->pgno,
        pMemPage->dbHdrOffset,
        pMemPage->offsetEntries,
        pMemPage->pgHdrOffset
      );
      break;
    }
  }
  assert(i<CESHIM_MAX_OFFSET_ENTRIES); // ceshimGetUnmappedDstPgno didn't work properly
  return rc;
}

static int ceshimSavePagemap(ceshim_file *p){
  ceshim_pagemap *pagemap = &p->pInfo->pagemap;
  return ceshimWriteUncompressed(p, 1, CESHIM_DB_HEADER_PGR_SZ, (void *)pagemap, CESHIM_DB_HEADER_MAP_SZ);
}

static int ceshimSetMappedPgno(ceshim_file *p, sqlite3_uint64 iOfst, Pgno lwrPgno, CeshimCompressedSize uSz){
  ceshim_pagemap *pagemap = &p->pInfo->pagemap;
  if( pagemap->nCount < CESHIM_MAX_PAGE_MAP_ENTRIES ){
    pagemap->currPageOfst += uSz;
    Pgno uppPgno = (Pgno)(iOfst/p->pageSize+1);
    pagemap->entries[pagemap->nCount].uppPgno = uppPgno;
    pagemap->entries[pagemap->nCount].lwrPgno = lwrPgno;
    pagemap->nCount++;
    return ceshimSavePagemap(p);
  }
  return SQLITE_ERROR;
}

static int ceshimGetPageNos(
  const ceshim_file *p,
  sqlite_uint64 iOfst,
  Pgno *uppPgno,
  Pgno *mappedPgno
){
  Pgno _uppPgno = (Pgno)(iOfst/p->pageSize+1);
  if (uppPgno) *uppPgno = _uppPgno;
  ceshim_pagemap *pagemap = &p->pInfo->pagemap;
  for(int i=0; i<pagemap->nCount; i++){
    if( pagemap->entries[i].uppPgno == _uppPgno ){
      if( mappedPgno )
        *mappedPgno = pagemap->entries[i].lwrPgno;
      return SQLITE_OK;
    }
  }
  /*
  if( iOfst < p->pageSize ){
    *mappedPgno = 1;
//    ceshimSetMappedPgno(p, iOfst, 1);
    return SQLITE_OK;
  }*/
  return SQLITE_ERROR;
}

static Pgno ceshimGetUnmappedDstPgno(ceshim_file *p, sqlite_uint64 iOfst, CeshimCompressedSize uSz){
  assert( ceshimGetPageNos(p, iOfst, NULL, NULL) == SQLITE_ERROR );
  ceshim_pagemap *pagemap = &p->pInfo->pagemap;
  u32 realPageSize = p->pageSize - (pagemap->currPgno == 1 ? CESHIM_DB_HEADER_SIZE : 0) - CESHIM_PAGE_HEADER_SIZE;
  if( pagemap->currPageOfst+uSz > realPageSize ){
    pagemap->currPageOfst = 0;
    pagemap->currPgno++;
  }
  ceshimSetMappedPgno(p, iOfst, pagemap->currPgno, uSz);
  return pagemap->currPgno;
}

/*
** Close a ceshim-file.
*/
static int ceshimClose(sqlite3_file *pFile){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  ceshim_printf(pInfo, "%s.xClose(%s)", pInfo->zVfsName, p->zFName);

  if( p->pPager ){
    // save pager counts
    u8 buf[4];
    sqlite3Put4byte(buf, pInfo->pagemap.lwrPageFile);
    rc = ceshimWriteUncompressed(p, 1, 28, buf, 4);

    if( (rc = ceshimSavePagemap(p))==SQLITE_OK ){
      for(int i=0; i<p->nTransactions; i++){
        if( (rc = sqlite3PagerCommitPhaseOne(p->pPager, NULL, 0))==SQLITE_OK ){
          sqlite3PagerCommitPhaseTwo(p->pPager);
        }
      }
      p->nTransactions = 0;

      if( rc==SQLITE_OK ){
        sqlite3PagerUnref(pInfo->pPage1->pDbPage);
        if( (rc = sqlite3PagerClose(p->pPager))==SQLITE_OK ){
          p->pPager = NULL;
        }
      }
    }
  }
  
  if( (rc == SQLITE_OK) && ((rc = p->pReal->pMethods->xClose(p->pReal)) == SQLITE_OK) ){
    sqlite3_free((void*)p->base.pMethods);
    p->base.pMethods = NULL;
  }

  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

static int ceshimPagerGet(
  ceshim_file *pFile,
  Pgno pgno,          /* Page number to fetch */
  DbPage **ppPage,    /* Write a pointer to the page here */
  int flags           /* PAGER_GET_XXX flags */
){
  int rc=SQLITE_OK;
  ceshim_info *pInfo = pFile->pInfo;
  /*if( pgno==1 && pInfo->pPage1 ){
    *ppPage = pInfo->pPage1->pDbPage;
  }else*/{
    rc=sqlite3PagerGet(pFile->pPager, pgno, ppPage, flags);
  }
  return rc;
}

/*
** Read data from a ceshim-file.
*/
static int ceshimRead(
  sqlite3_file *pFile,
  void *zBuf,
  int iAmt,
  sqlite_int64 iOfst
){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  ceshim_printf(pInfo, "%s.xRead(%s,n=%d,ofst=%lld)", pInfo->zVfsName, p->zFName, iAmt, iOfst);

  if( p->pPager ){
    DbPage *pPage;
    Pgno uppPgno, mappedPgno;
    if( (rc = ceshimGetPageNos(p, iOfst, &uppPgno, &mappedPgno)) == SQLITE_ERROR ){
      if( iOfst < p->pageSize ) {
        mappedPgno = 1;
        rc = SQLITE_OK;
      }
    }
    if( rc==SQLITE_OK &&  (rc = ceshimPagerGet(p, mappedPgno, &pPage, 0)) == SQLITE_OK ){
      CeshimCompressedOffset cmprPgOfst;
      CeshimCompressedSize uPgSz;
      CeshimMemPage *pMemPage = memPageFromDbPage(pPage, mappedPgno);
      cmprPgOfst = ceshimGetPageOffset(p, pMemPage, iOfst, &uPgSz);
      if( uPgSz > 0 ){
        int iDstAmt = p->pageSize;
        void *pBuf = sqlite3_malloc(p->pageSize);
        pInfo->xUncompress(
          NULL,
          pBuf,
          &iDstAmt,
          (char *)pMemPage->aData
            +pMemPage->dbHdrOffset
            +pMemPage->pgHdrOffset
            +cmprPgOfst,
          uPgSz
        );
        u16 uBufOfst = iOfst % p->pageSize;
        memcpy(zBuf, pBuf+uBufOfst, iAmt);
        sqlite3_free(pBuf);
      }else{
        memset(zBuf, 0, iAmt);
      }
      sqlite3PagerUnref(pPage);
    }
    else return SQLITE_OK;
  }else{
    rc = p->pReal->pMethods->xRead(p->pReal, zBuf, iAmt, iOfst);
  }
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Write data to a ceshim-file.
*/
static int ceshimWrite(
  sqlite3_file *pFile,
  const void *zBuf,
  int iAmt,
  sqlite_int64 iOfst
){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;

  if( p->pPager ){
    DbPage *pPage;
    Pgno uppPgno, mappedPgno;

    if( rc==SQLITE_OK ){
      // compress
      int pnDest = pInfo->xCompressBound(NULL, iAmt);
      void* pBuf = sqlite3_malloc(pnDest);
      pInfo->xCompress(NULL, pBuf, &pnDest, (void *)zBuf, iAmt);

      if( ceshimGetPageNos(p, iOfst, &uppPgno, &mappedPgno) == SQLITE_ERROR ){
        mappedPgno = ceshimGetUnmappedDstPgno(p, iOfst, pnDest);
      }

      ceshim_printf(pInfo, "%s.xWrite(%s, Pgno=%u->%u, offset=%06lld, amt=%06d,)", pInfo->zVfsName, p->zFName, uppPgno, mappedPgno, iOfst, iAmt);

      if( (rc = ceshimPagerGet(p, mappedPgno, &pPage, 0)) == SQLITE_OK ){
        // write
        CeshimMemPage *pMemPage = memPageFromDbPage(pPage, mappedPgno);
        if( (rc = ceshimSetPageOffset(pMemPage, p, iOfst, pnDest)) == SQLITE_OK ){
          CeshimCompressedOffset cmprPgOfst = ceshimGetPageOffset(p, pMemPage, iOfst, NULL);
          if( (rc = ceshimPagerWrite(p, pPage)) == SQLITE_OK ){
            ceshim_printf(
              pInfo,
              "\n[compressed] %s.xWrite(%s, offset=%06lld, amt=%06d,)",
              pInfo->zVfsName,
              p->zFName,
              pMemPage->dbHdrOffset+pMemPage->pgHdrOffset+cmprPgOfst,
              pnDest
            );
            memcpy(
              pMemPage->aData
                +pMemPage->dbHdrOffset
                +pMemPage->pgHdrOffset
                +cmprPgOfst,
              pBuf,
              pnDest
            );

            // Keep track of sizes of upper and lower pagers
            if( pInfo->pagemap.uppPageFile<uppPgno ) pInfo->pagemap.uppPageFile = uppPgno;
            if( pInfo->pagemap.lwrPageFile<mappedPgno ) pInfo->pagemap.lwrPageFile = mappedPgno;
          }
        }
        sqlite3PagerUnref(pPage);

        // Need this for table to be available after CREATE TABLE.
        // Is ther a better way to do this ... or more efficient time to flush?
        //sqlite3PagerFlush(p->pPager);
      }
    }
  }else{
    ceshim_printf(pInfo, "%s.xWrite(%s, offset=%06lld, amt=%06d,)", pInfo->zVfsName, p->zFName, iOfst, iAmt);
    rc = p->pReal->pMethods->xWrite(p->pReal, zBuf, iAmt, iOfst);
  }
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Truncate a ceshim-file.
*/
static int ceshimTruncate(sqlite3_file *pFile, sqlite_int64 size){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  ceshim_printf(pInfo, "%s.xTruncate(%s,%lld)", pInfo->zVfsName, p->zFName, size);
  rc = p->pReal->pMethods->xTruncate(p->pReal, size);
  ceshim_printf(pInfo, " -> %d\n", rc);
  return rc;
}

/*
** Sync a ceshim-file.
*/
static int ceshimSync(sqlite3_file *pFile, int flags){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  int i;
  char zBuf[100];
  memcpy(zBuf, "|0", 3);
  i = 0;
  if( flags & SQLITE_SYNC_FULL )        strappend(zBuf, &i, "|FULL");
  else if( flags & SQLITE_SYNC_NORMAL ) strappend(zBuf, &i, "|NORMAL");
  if( flags & SQLITE_SYNC_DATAONLY )    strappend(zBuf, &i, "|DATAONLY");
  if( flags & ~(SQLITE_SYNC_FULL|SQLITE_SYNC_DATAONLY) ){
    sqlite3_snprintf(sizeof(zBuf)-i, &zBuf[i], "|0x%x", flags);
  }
  ceshim_printf(pInfo, "%s.xSync(%s,%s)", pInfo->zVfsName, p->zFName, &zBuf[1]);
  rc = p->pReal->pMethods->xSync(p->pReal, flags);
  ceshim_printf(pInfo, " -> %d\n", rc);
  return rc;
}

/*
** Return ficticious uncompressed file size based on number of pages from source pager
** otherwise internal checks in pager.c will fail.
*/
static int ceshimFileSize(sqlite3_file *pFile, sqlite_int64 *pSize){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  ceshim_printf(pInfo, "%s.xFileSize(%s)", pInfo->zVfsName, p->zFName);
  if(p->pPager ){
    *pSize = pInfo->pagemap.uppPageFile * p->pageSize;
    rc = SQLITE_OK;
  }else{
    rc = p->pReal->pMethods->xFileSize(p->pReal, pSize);
  }
  ceshim_print_errcode(pInfo, " -> %s,", rc);
  ceshim_printf(pInfo, " size=%lld\n", *pSize);
  return rc;
}

/*
** Return the name of a lock.
*/
static const char *lockName(int eLock){
  const char *azLockNames[] = {
     "NONE", "SHARED", "RESERVED", "PENDING", "EXCLUSIVE"
  };
  if( eLock<0 || eLock>=sizeof(azLockNames)/sizeof(azLockNames[0]) ){
    return "???";
  }else{
    return azLockNames[eLock];
  }
}

/*
** Lock a ceshim-file.
** Never lock database file for upper pager as it doesn't directly control database file anymore.
*/
static int ceshimLock(sqlite3_file *pFile, int eLock){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  ceshim_printf(pInfo, "%s.xLock(%s,%s) BYPASS", pInfo->zVfsName, p->zFName, lockName(eLock));
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Unlock a ceshim-file.
** Never unlock database file for upper pager as it doesn't directly control database file anymore.
*/
static int ceshimUnlock(sqlite3_file *pFile, int eLock){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  ceshim_printf(pInfo, "%s.xUnlock(%s,%s) BYPASS", pInfo->zVfsName, p->zFName, lockName(eLock));
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Check if another file-handle holds a RESERVED lock on a ceshim-file.
** Bypass checks here since upper pager doesn't directly control database file anymore.
*/
static int ceshimCheckReservedLock(sqlite3_file *pFile, int *pResOut){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  *pResOut = 0; // not locked
  ceshim_printf(pInfo, "%s.xCheckReservedLock(%s,%d) BYPASS", pInfo->zVfsName, p->zFName);
  ceshim_print_errcode(pInfo, " -> %s", rc);
  ceshim_printf(pInfo, ", out=%d\n", *pResOut);
  ceshim_printf(pInfo, "\n");
  return rc;
}

/*
** File control method. For custom operations on a ceshim-file.
*/
static int ceshimFileControl(sqlite3_file *pFile, int op, void *pArg){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  char zBuf[100];
  char *zOp;
  switch( op ){
    case SQLITE_FCNTL_LOCKSTATE:    zOp = "LOCKSTATE";          break;
    case SQLITE_GET_LOCKPROXYFILE:  zOp = "GET_LOCKPROXYFILE";  break;
    case SQLITE_SET_LOCKPROXYFILE:  zOp = "SET_LOCKPROXYFILE";  break;
    case SQLITE_LAST_ERRNO:         zOp = "LAST_ERRNO";         break;
    case SQLITE_FCNTL_SIZE_HINT: {
      sqlite3_snprintf(sizeof(zBuf), zBuf, "SIZE_HINT,%lld",
                       *(sqlite3_int64*)pArg);
      zOp = zBuf;
      break;
    }
    case SQLITE_FCNTL_CHUNK_SIZE: {
      sqlite3_snprintf(sizeof(zBuf), zBuf, "CHUNK_SIZE,%d", *(int*)pArg);
      zOp = zBuf;
      break;
    }
    case SQLITE_FCNTL_FILE_POINTER: zOp = "FILE_POINTER";       break;
    case SQLITE_FCNTL_SYNC_OMITTED: zOp = "SYNC_OMITTED";       break;
    case SQLITE_FCNTL_WIN32_AV_RETRY: zOp = "WIN32_AV_RETRY";   break;
    case SQLITE_FCNTL_PERSIST_WAL:  zOp = "PERSIST_WAL";        break;
    case SQLITE_FCNTL_OVERWRITE:    zOp = "OVERWRITE";          break;
    case SQLITE_FCNTL_VFSNAME:      zOp = "VFSNAME";            break;
    case SQLITE_FCNTL_TEMPFILENAME: zOp = "TEMPFILENAME";       break;
    case SQLITE_FCNTL_DB_UNCHANGED: zOp = "DB_UNCHANGED";       break;
    case SQLITE_FCNTL_PRAGMA: {
      const char *const* a = (const char*const*)pArg;
      sqlite3_snprintf(sizeof(zBuf), zBuf, "PRAGMA,[%s,%s]",a[1],a[2]);
      zOp = zBuf;
      break;
    }
    default: {
      sqlite3_snprintf(sizeof zBuf, zBuf, "%d", op);
      zOp = zBuf;
      break;
    }
  }
  ceshim_printf(pInfo, "%s.xFileControl(%s,%s)", pInfo->zVfsName, p->zFName, zOp);
  rc = p->pReal->pMethods->xFileControl(p->pReal, op, pArg);
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  if( op==SQLITE_FCNTL_VFSNAME && rc==SQLITE_OK ){
    *(char**)pArg = sqlite3_mprintf("ceshim.%s/%z",
                                    pInfo->zVfsName, *(char**)pArg);
  }
  if( (op==SQLITE_FCNTL_PRAGMA || op==SQLITE_FCNTL_TEMPFILENAME)
   && rc==SQLITE_OK && *(char**)pArg ){
    ceshim_printf(pInfo, "%s.xFileControl(%s,%s) returns %s", pInfo->zVfsName, p->zFName, zOp, *(char**)pArg);
  }
  return rc;
}

/*
** Return the sector-size in bytes for a ceshim-file.
*/
static int ceshimSectorSize(sqlite3_file *pFile){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  ceshim_printf(pInfo, "%s.xSectorSize(%s)", pInfo->zVfsName, p->zFName);
  rc = p->pReal->pMethods->xSectorSize(p->pReal);
  ceshim_printf(pInfo, " -> %d\n", rc);
  return rc;
}

/*
** Return the device characteristic flags supported by a ceshim-file.
*/
static int ceshimDeviceCharacteristics(sqlite3_file *pFile){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  ceshim_printf(pInfo, "%s.xDeviceCharacteristics(%s)", pInfo->zVfsName, p->zFName);
  rc = p->pReal->pMethods->xDeviceCharacteristics(p->pReal);
  ceshim_printf(pInfo, " -> 0x%08x\n", rc);
  return rc;
}

/*
** Shared-memory operations.
*/
static int ceshimShmLock(sqlite3_file *pFile, int ofst, int n, int flags){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  char zLck[100];
  int i = 0;
  memcpy(zLck, "|0", 3);
  if( flags & SQLITE_SHM_UNLOCK )    strappend(zLck, &i, "|UNLOCK");
  if( flags & SQLITE_SHM_LOCK )      strappend(zLck, &i, "|LOCK");
  if( flags & SQLITE_SHM_SHARED )    strappend(zLck, &i, "|SHARED");
  if( flags & SQLITE_SHM_EXCLUSIVE ) strappend(zLck, &i, "|EXCLUSIVE");
  if( flags & ~(0xf) ){
     sqlite3_snprintf(sizeof(zLck)-i, &zLck[i], "|0x%x", flags);
  }
  ceshim_printf(pInfo, "%s.xShmLock(%s,ofst=%d,n=%d,%s)", pInfo->zVfsName, p->zFName, ofst, n, &zLck[1]);
  rc = p->pReal->pMethods->xShmLock(p->pReal, ofst, n, flags);
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}
static int ceshimShmMap(
  sqlite3_file *pFile,
  int iRegion,
  int szRegion,
  int isWrite,
  void volatile **pp
){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  ceshim_printf(pInfo, "%s.xShmMap(%s,iRegion=%d,szRegion=%d,isWrite=%d,*)", pInfo->zVfsName, p->zFName, iRegion, szRegion, isWrite);
  rc = p->pReal->pMethods->xShmMap(p->pReal, iRegion, szRegion, isWrite, pp);
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}
static void ceshimShmBarrier(sqlite3_file *pFile){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  ceshim_printf(pInfo, "%s.xShmBarrier(%s)\n", pInfo->zVfsName, p->zFName);
  p->pReal->pMethods->xShmBarrier(p->pReal);
}
static int ceshimShmUnmap(sqlite3_file *pFile, int delFlag){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  ceshim_printf(pInfo, "%s.xShmUnmap(%s,delFlag=%d)", pInfo->zVfsName, p->zFName, delFlag);
  rc = p->pReal->pMethods->xShmUnmap(p->pReal, delFlag);
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}


static void pageReinit(DbPage *pData) {

}


/*
** Open a ceshim file handle.
*/
static int ceshimOpen(
    sqlite3_vfs *pVfs,
    const char *zName,
    sqlite3_file *pFile,
    int flags,
    int *pOutFlags
){
  unsigned char zDbHeader[100];
  u8 nReserve;
  int rc;

  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;

  p->pInfo = pInfo;
  p->zFName = zName ? fileTail(zName) : "<temp>";
  p->pReal = (sqlite3_file *)&p[1];
  p->pPager = NULL;

  // open file
  rc = pRoot->xOpen(pRoot, zName, p->pReal, flags, pOutFlags);
  ceshim_printf(pInfo, "%s.xOpen(%s,flags=0x%x)",pInfo->zVfsName, p->zFName, flags);

  if( rc==SQLITE_OK ){
    // hook up I/O methods
    if( p->pReal->pMethods ){
      sqlite3_io_methods *pNew = sqlite3_malloc( sizeof(*pNew) );
      const sqlite3_io_methods *pSub = p->pReal->pMethods;
      memset(pNew, 0, sizeof(*pNew));
      pNew->iVersion = pSub->iVersion;
      pNew->xClose = ceshimClose;
      pNew->xRead = ceshimRead;
      pNew->xWrite = ceshimWrite;
      pNew->xTruncate = ceshimTruncate;
      pNew->xSync = ceshimSync;
      pNew->xFileSize = ceshimFileSize;
      pNew->xLock = ceshimLock;
      pNew->xUnlock = ceshimUnlock;
      pNew->xCheckReservedLock = ceshimCheckReservedLock;
      pNew->xFileControl = ceshimFileControl;
      pNew->xSectorSize = ceshimSectorSize;
      pNew->xDeviceCharacteristics = ceshimDeviceCharacteristics;
      if( pNew->iVersion>=2 ){
        pNew->xShmMap = pSub->xShmMap ? ceshimShmMap : 0;
        pNew->xShmLock = pSub->xShmLock ? ceshimShmLock : 0;
        pNew->xShmBarrier = pSub->xShmBarrier ? ceshimShmBarrier : 0;
        pNew->xShmUnmap = pSub->xShmUnmap ? ceshimShmUnmap : 0;
      }
      pFile->pMethods = pNew;
    }

    // create pager to handle I/O to compressed/encrypted underlying db
    if( flags & (SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TRANSIENT_DB) ){
      rc = sqlite3PagerOpen(pInfo->pRootVfs, &p->pPager, zName, EXTRA_SIZE, 0, flags, pageReinit);
//      rc = sqlite3PagerSetJournalMode(p->pPager, PAGER_JOURNALMODE_MEMORY);
        if( rc==SQLITE_OK ){
          //rc = sqlite3PagerLockingMode(p->pPager, PAGER_LOCKINGMODE_NORMAL);
          //sqlite3PagerSetMmapLimit(pBt->pPager, db->szMmap); /* advisory, except if 0 */

          if( (rc = sqlite3PagerReadFileheader(p->pPager,sizeof(zDbHeader),zDbHeader)) == SQLITE_OK ){
            p->pageSize = (zDbHeader[16]<<8) | (zDbHeader[17]<<16);
            if( p->pageSize<512 || p->pageSize>SQLITE_MAX_PAGE_SIZE
               || ((p->pageSize-1)&p->pageSize)!=0 ){
              p->pageSize = 0; // sqlite3PagerSetPagesize will set page size
              nReserve = 0;
            }else{
              nReserve = zDbHeader[20];
            }
            if( (rc = sqlite3PagerSetPagesize(p->pPager, &p->pageSize, nReserve)) == SQLITE_OK ){
              p->usableSize = p->pageSize - nReserve;
              sqlite3PagerSetCachesize(p->pPager, SQLITE_DEFAULT_CACHE_SIZE);
              //rc = sqlite3PagerSetJournalMode(p->pPager, PAGER_JOURNALMODE_MEMORY);
              //sqlite3PagerJournalSizeLimit(p->pPager, -1);
              if( (rc = sqlite3PagerSharedLock(p->pPager)) == SQLITE_OK ){
                DbPage *pDbPage1;
                if( (rc = sqlite3PagerGet(p->pPager, 1, &pDbPage1, 0)) == SQLITE_OK ){
                  pInfo->pPage1 = memPageFromDbPage(pDbPage1, 1);
                  int nPageFile = 0;
                  sqlite3PagerPagecount(p->pPager, &nPageFile);
                  if( nPageFile == 0 ){
                    if(( rc = ceshimNewDatabase(p))==SQLITE_OK ){
                    }
                  }else{
                    // restore page map table
                    memcpy(&pInfo->pagemap, pInfo->pPage1->aData+CESHIM_DB_HEADER_PGR_SZ, CESHIM_DB_HEADER_MAP_SZ);
                  }
                  /* reminder: do not call sqlite3PagerUnref(pDbPage1) here as this will
                     cause pager state to reset to PAGER_OPEN which is not desirable for writing to pager. */
                }
              }
            }
          }
        }else{
          if( pInfo && p->pPager ){
            sqlite3PagerClose(p->pPager);
          }
        }
      }
    }

  ceshim_print_errcode(pInfo, " -> %s", rc);
  if( pOutFlags ){
    ceshim_printf(pInfo, ", outFlags=0x%x\n", *pOutFlags);
  }else{
    ceshim_printf(pInfo, "\n");
  }
  return rc;
}

/*
** Delete the file located at zPath. If the dirSync argument is true,
** ensure the file-system modifications are synced to disk before
** returning.
*/
static int ceshimDelete(sqlite3_vfs *pVfs, const char *zPath, int dirSync){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  int rc;
  ceshim_printf(pInfo, "%s.xDelete(\"%s\",%d)", pInfo->zVfsName, zPath, dirSync);
  rc = pRoot->xDelete(pRoot, zPath, dirSync);
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Test for access permissions. Return true if the requested permission
** is available, or false otherwise.
*/
static int ceshimAccess(
  sqlite3_vfs *pVfs,
  const char *zPath,
  int flags,
  int *pResOut
){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  int rc;
  ceshim_printf(pInfo, "%s.xAccess(\"%s\",%d)", pInfo->zVfsName, zPath, flags);
  rc = pRoot->xAccess(pRoot, zPath, flags, pResOut);
  ceshim_print_errcode(pInfo, " -> %s", rc);
  ceshim_printf(pInfo, ", out=%d\n", *pResOut);
  return rc;
}

/*
** Populate buffer zOut with the full canonical pathname corresponding
** to the pathname in zPath. zOut is guaranteed to point to a buffer
** of at least (DEVSYM_MAX_PATHNAME+1) bytes.
*/
static int ceshimFullPathname(
  sqlite3_vfs *pVfs,
  const char *zPath,
  int nOut,
  char *zOut
){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  int rc;
  ceshim_printf(pInfo, "%s.xFullPathname(\"%s\")", pInfo->zVfsName, zPath);
  rc = pRoot->xFullPathname(pRoot, zPath, nOut, zOut);
  ceshim_print_errcode(pInfo, " -> %s", rc);
  ceshim_printf(pInfo, ", out=\"%.*s\"\n", nOut, zOut);
  return rc;
}

/*
** Open the dynamic library located at zPath and return a handle.
*/
static void *ceshimDlOpen(sqlite3_vfs *pVfs, const char *zPath){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  ceshim_printf(pInfo, "%s.xDlOpen(\"%s\")\n", pInfo->zVfsName, zPath);
  return pRoot->xDlOpen(pRoot, zPath);
}

/*
** Populate the buffer zErrMsg (size nByte bytes) with a human readable
** utf-8 string describing the most recent error encountered associated
** with dynamic libraries.
*/
static void ceshimDlError(sqlite3_vfs *pVfs, int nByte, char *zErrMsg){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  ceshim_printf(pInfo, "%s.xDlError(%d)", pInfo->zVfsName, nByte);
  pRoot->xDlError(pRoot, nByte, zErrMsg);
  ceshim_printf(pInfo, " -> \"%s\"", zErrMsg);
}

/*
** Return a pointer to the symbol zSymbol in the dynamic library pHandle.
*/
static void (*ceshimDlSym(sqlite3_vfs *pVfs,void *p,const char *zSym))(void){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  ceshim_printf(pInfo, "%s.xDlSym(\"%s\")\n", pInfo->zVfsName, zSym);
  return pRoot->xDlSym(pRoot, p, zSym);
}

/*
** Close the dynamic library handle pHandle.
*/
static void ceshimDlClose(sqlite3_vfs *pVfs, void *pHandle){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  ceshim_printf(pInfo, "%s.xDlOpen()\n", pInfo->zVfsName);
  pRoot->xDlClose(pRoot, pHandle);
}

/*
** Populate the buffer pointed to by zBufOut with nByte bytes of
** random data.
*/
static int ceshimRandomness(sqlite3_vfs *pVfs, int nByte, char *zBufOut){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  ceshim_printf(pInfo, "%s.xRandomness(%d)\n", pInfo->zVfsName, nByte);
  return pRoot->xRandomness(pRoot, nByte, zBufOut);
}

/*
** Sleep for nMicro microseconds. Return the number of microseconds
** actually slept.
*/
static int ceshimSleep(sqlite3_vfs *pVfs, int nMicro){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xSleep(pRoot, nMicro);
}

/*
** Return the current time as a Julian Day number in *pTimeOut.
*/
static int ceshimCurrentTime(sqlite3_vfs *pVfs, double *pTimeOut){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xCurrentTime(pRoot, pTimeOut);
}
static int ceshimCurrentTimeInt64(sqlite3_vfs *pVfs, sqlite3_int64 *pTimeOut){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xCurrentTimeInt64(pRoot, pTimeOut);
}

/*
** Return the emost recent error code and message
*/
static int ceshimGetLastError(sqlite3_vfs *pVfs, int iErr, char *zErr){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xGetLastError(pRoot, iErr, zErr);
}

/*
** Override system calls.
*/
static int ceshimSetSystemCall(
  sqlite3_vfs *pVfs,
  const char *zName,
  sqlite3_syscall_ptr pFunc
){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xSetSystemCall(pRoot, zName, pFunc);
}
static sqlite3_syscall_ptr ceshimGetSystemCall(
  sqlite3_vfs *pVfs,
  const char *zName
){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xGetSystemCall(pRoot, zName);
}
static const char *ceshimNextSystemCall(sqlite3_vfs *pVfs, const char *zName){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xNextSystemCall(pRoot, zName);
}


/*
** Clients invoke this routine to construct a new ceshim.
**
** Return SQLITE_OK on success.
**
** SQLITE_NOMEM is returned in the case of a memory allocation error.
** SQLITE_NOTFOUND is returned if zOldVfsName does not exist.
*/
int ceshim_register(
  const char *zName,                /* Name of the newly constructed VFS */
  const char *zParent,              /* Name of the underlying VFS */
  void *pCtx,
  int (*xCompressBound)(void *, int nSrc),
  int (*xCompress)(void *, char *aDest, int *pnDest, char *aSrc, int nSrc),
  int (*xUncompress)(void *, char *aDest, int *pnDest, char *aSrc, int nSrc),
  int (*xOut)(const char*,void*),   /* Output routine. */
  void *pOutArg,                    /* 2nd argument to xOut.  ex: stderr */
  int makeDefault                   /* True to make the new VFS the default */
){
  sqlite3_vfs *pNew;
  sqlite3_vfs *pRoot;
  ceshim_info *pInfo;
  int nName;
  int nByte;

  pRoot = sqlite3_vfs_find(zParent);
  if( pRoot==0 ) return SQLITE_NOTFOUND;
  nName = (int)strlen(zName);

  // Allocate memory for a new sqlite3_vfs, ceshim_info and the name of the new VFS.
  nByte = sizeof(*pNew) + sizeof(*pInfo) + nName + 1;
  pNew = sqlite3_malloc( nByte );
  if( pNew==0 ) return SQLITE_NOMEM;
  memset(pNew, 0, nByte);

  // Hook up the rest of the allocated memory
  pInfo = (ceshim_info*)&pNew[1];
  pNew->zName = (char*)&pInfo[1];

  // Intialize data
  memcpy((char*)&pInfo[1], zName, nName+1);
  pNew->iVersion = pRoot->iVersion;
  pNew->szOsFile = pRoot->szOsFile + sizeof(ceshim_file);
  pNew->mxPathname = pRoot->mxPathname;
  pNew->pAppData = pInfo;
  pNew->xOpen = ceshimOpen;
  pNew->xDelete = ceshimDelete;
  pNew->xAccess = ceshimAccess;
  pNew->xFullPathname = ceshimFullPathname;
  pNew->xDlOpen = pRoot->xDlOpen==0 ? 0 : ceshimDlOpen;
  pNew->xDlError = pRoot->xDlError==0 ? 0 : ceshimDlError;
  pNew->xDlSym = pRoot->xDlSym==0 ? 0 : ceshimDlSym;
  pNew->xDlClose = pRoot->xDlClose==0 ? 0 : ceshimDlClose;
  pNew->xRandomness = ceshimRandomness;
  pNew->xSleep = ceshimSleep;
  pNew->xCurrentTime = ceshimCurrentTime;
  pNew->xGetLastError = pRoot->xGetLastError==0 ? 0 : ceshimGetLastError;
  if( pNew->iVersion>=2 ){
    pNew->xCurrentTimeInt64 = pRoot->xCurrentTimeInt64==0 ? 0 : ceshimCurrentTimeInt64;
    if( pNew->iVersion>=3 ){
      pNew->xSetSystemCall = pRoot->xSetSystemCall==0 ? 0 : ceshimSetSystemCall;
      pNew->xGetSystemCall = pRoot->xGetSystemCall==0 ? 0 : ceshimGetSystemCall;
      pNew->xNextSystemCall = pRoot->xNextSystemCall==0 ? 0 : ceshimNextSystemCall;
    }
  }
  pInfo->pRootVfs = pRoot;
  pInfo->xOut = xOut;
  pInfo->pOutArg = pOutArg;
  pInfo->zVfsName = pNew->zName;
  pInfo->pCeshimVfs = pNew;
  pInfo->xCompressBound = xCompressBound;
  pInfo->xCompress = xCompress;
  pInfo->xUncompress = xUncompress;
  pInfo->pagemap.currPgno = 1;

  ceshim_printf(pInfo, "%s.enabled_for(\"%s\")\n", pInfo->zVfsName, pRoot->zName);
  return sqlite3_vfs_register(pNew, makeDefault);
}
