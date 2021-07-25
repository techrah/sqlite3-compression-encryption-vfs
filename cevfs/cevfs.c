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

#ifndef SQLITE_AMALGAMATION
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"
#include "sqliteInt.h"
#include "pager.h"
#include "btreeInt.h"
#endif
#include <sys/stat.h>
#include "cevfs.h"

// Standard Sqlite3 pager header
#define CEVFS_DB_HEADER1_OFST      000
#define CEVFS_DB_HEADER1_SZ        100

// cevfs-specific pager header
#define CEVFS_DB_HEADER2_OFST      CEVFS_DB_HEADER1_OFST+CEVFS_DB_HEADER1_SZ
#define CEVFS_DB_HEADER2_SZ        100

// Total header size
#define CEVFS_DB_HEADER_SIZE       (CEVFS_DB_HEADER1_SZ + CEVFS_DB_HEADER2_SZ)

// Offset to master map table, starts just after header
#define CEVFS_DB_MMTBL_OFST        CEVFS_DB_HEADER2_OFST+CEVFS_DB_HEADER2_SZ

#define CEVFS_FILE_SCHEMA_NO         1
#define CEVFS_FIRST_MAPPED_PAGE      3

#ifdef SQLITE_DEBUG
#define CEVFS_PRINTF(a,b,...) cevfs_printf(a,b,##__VA_ARGS__)
#else
#define CEVFS_PRINTF(a,b,...)
#endif

SQLITE_PRIVATE int sqlite3PagerCloseShim(Pager *pPager, sqlite3* db){
#if SQLITE_VERSION_NUMBER < 3016000
  return sqlite3PagerClose(pPager);
#else
  return sqlite3PagerClose(pPager, db);
#endif
}

#ifndef EXTRA_SIZE
#define EXTRA_SIZE sizeof(MemPage)
#endif

// Compression size and offset types
typedef u16 CevfsCmpSize;
typedef u16 CevfsCmpOfst;

/*
** The header string that appears at the beginning of every
** SQLite database.
*/
#ifndef SQLITE_AMALGAMATION
static const char zMagicHeader[] = SQLITE_FILE_HEADER;
#endif

/*
** Keeps track of data we need to persist for the pager.
** This will be stored uncompressed at offset 100-199.
*/
typedef struct cevfs_header cevfs_header;
struct cevfs_header {
  u8 schema;                           // 01 file schema version number
  Pgno currPgno;                       // 04 curr lower pager pgno being filled
  CevfsCmpOfst currPageOfst;           // 02 curr offset for next compressed page
  u16 pgMapCnt;                        // 02 num elements of last page map
  u32 uppPgSz;                         // 04 Upper pager page size. Could be different from lower pager's
  Pgno uppPageFile;                    // 04 max pgno in upper pager, used to report filesize
  u16 mmTblMaxCnt;                     // 02 max entries avail for master map table, computed when table is loaded
  u16 mmTblCurrCnt;                    // 02 curr total elements used in master map table
  unsigned char reserved[79];          // 79 pad structure to 100 bytes
};

/*
** Page 1, bytes from offset CEVFS_DB_HEADER2_OFST to end of page, will have a master map for coordinating
** all the other mapping tables. If table becomes full, perhaps a larger pagesize will help.
** This can be set using PRAGMA page_size (e.g.: PRAGMA page_size = 2048)
*/
typedef struct CevfsMMTblEntry CevfsMMTblEntry;
struct __attribute__ ((__packed__)) CevfsMMTblEntry {
  Pgno lwrPgno;                        // 04 lower pager pgno where actual page map data is stored
};

/*
** Each time we read a page, it'll be associated with a CevfsMemPage
** to store temporary in-memory data that belongs to this page.
*/
typedef struct CevfsMemPage CevfsMemPage;
struct CevfsMemPage {
  DbPage *pDbPage;                     // Pager page handle
  Pgno pgno;                           // The pgno to which this belongs
  u16 dbHdrOffset;                     // Offset to the beginning of the header
  u16 pgHdrOffset;                     // Offset to the beginning of the data
  u8 *aData;                           // Pointer to disk image of the page data
};

/*
** Mapping table for uncompressed to compressed content.
** The table is stored on page 2 at offset 0.
** The maximum size of table depends on the pager page size.
** If that is not enough, multiple tables will be used.
** As each new table is created, it is stored on the next available page.
*/
typedef struct cevfs_map_entry cevfs_map_entry;
struct __attribute__ ((__packed__)) cevfs_map_entry {
  Pgno lwrPgno;                        // 04 mapped lower pager pgno
  CevfsCmpSize cmprSz;                 // 02 size of compressed page
  CevfsCmpOfst cmprOfst;               // 02 lower page offset for compressed page
};

/*
** An instance of this structure is attached to each cevfs VFS to
** provide auxiliary non-persisted information.
*/
typedef struct cevfs_file cevfs_file;
typedef struct cevfs_info cevfs_info;
struct cevfs_info {
  sqlite3_vfs *pRootVfs;               // The underlying real VFS
  const char *zVfsName;                // Name of this VFS
  sqlite3_vfs *pCevfsVfs;              // Pointer back to the cevfs VFS
  cevfs_file *pFile;                   // Pointer back to the cevfs_file representing the dest. db.
  sqlite3 *pDb;                        // Pointer to sqlite3 instance
  int cerod_activated;                 // if extension is enabled, make sure read only

  // Pointers to custom compress/encryption functions implemented by the user
  void *pCtx;
  t_xAutoDetect xAutoDetect;

  u32 upperPgSize;                     // Temp storage for upperPgSize
};

/*
** The sqlite3_file object for the shim.
*/
struct cevfs_file {
  sqlite3_file base;                   // Base class.  Must be first
  sqlite3_file *pReal;                 // The real underlying file
  cevfs_info *pInfo;                   // Custom info for this file
  const char *zFName;                  // Base name of the file
  char *zUppJournalPath;               // Path to redirect upper journal
  unsigned char zDbHeader[100];        // Sqlite3 DB header
  cevfs_header cevfsHeader;            // Cevfs header with page mapping data
  CevfsMethods vfsMethods;             // Custom methods for compression/enctyption
  size_t nEncIvSz;                     // IV blob size in bytes for encryption/decryption routines

  // map
  CevfsMMTblEntry *mmTbl;              // The master mapping table
  u16 mmTblCurrIx;                     // Index of the current page map in mmTbl
  cevfs_map_entry *pPgMap;             // The current page map
  cevfs_map_entry *pBigEndianPgMap;    // Used for converting integers to big-endian when saving
  u16 pgMapMaxCnt;                     // Max entries for a page map, based on page size
  u16 pgMapSz;                         // Size in bytes for the page map allocation
  u32 nBytesPerPgMap;                  // Performance optimization premultiplication store

  // pager
  CevfsMemPage *pPage1;                // Page 1 of the pager
  Pager *pPager;                       // Pager for I/O with compressed/encrypted file
  Pgno lwrPageFile;                    // max pgno in lower pager, used to update pager header
  u32 pageSize;                        // Page size of the lower pager
  u32 usableSize;                      // Number of usable bytes on each page
  u8 nTransactions;                    // Number of open transactions on the pager

  // bools
  u8 bPgMapDirty:1;                    // Curr page map needs to be persisted
  u8 bReadOnly:1;                      // True when db was open for read-only
  u8 bCompressionEnabled:1;
  u8 bEncryptionEnabled:1;

};

/*
** Method declarations for cevfs_file.
*/
static int cevfsClose(sqlite3_file*);
static int cevfsRead(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
static int cevfsWrite(sqlite3_file*,const void*,int iAmt, sqlite3_int64);
static int cevfsTruncate(sqlite3_file*, sqlite3_int64 size);
static int cevfsSync(sqlite3_file*, int flags);
static int cevfsFileSize(sqlite3_file*, sqlite3_int64 *pSize);
static int cevfsLock(sqlite3_file*, int);
static int cevfsUnlock(sqlite3_file*, int);
static int cevfsCheckReservedLock(sqlite3_file*, int *);
static int cevfsFileControl(sqlite3_file*, int op, void *pArg);
static int cevfsSectorSize(sqlite3_file*);
static int cevfsDeviceCharacteristics(sqlite3_file*);
static int cevfsShmLock(sqlite3_file*,int,int,int);
static int cevfsShmMap(sqlite3_file*,int,int,int, void volatile **);
static void cevfsShmBarrier(sqlite3_file*);
static int cevfsShmUnmap(sqlite3_file*,int);

/*
** Method declarations for cevfs_vfs.
*/
static int cevfsOpen(sqlite3_vfs*, const char *, sqlite3_file*, int , int *);
static int cevfsDelete(sqlite3_vfs*, const char *zName, int syncDir);
static int cevfsAccess(sqlite3_vfs*, const char *zName, int flags, int *);
static int cevfsFullPathname(sqlite3_vfs*, const char *zName, int, char *);
static void *cevfsDlOpen(sqlite3_vfs*, const char *zFilename);
static void cevfsDlError(sqlite3_vfs*, int nByte, char *zErrMsg);
static void (*cevfsDlSym(sqlite3_vfs*,void*, const char *zSymbol))(void);
static void cevfsDlClose(sqlite3_vfs*, void*);
static int cevfsRandomness(sqlite3_vfs*, int nByte, char *zOut);
static int cevfsSleep(sqlite3_vfs*, int microseconds);
static int cevfsCurrentTime(sqlite3_vfs*, double*);
static int cevfsGetLastError(sqlite3_vfs*, int, char*);
static int cevfsCurrentTimeInt64(sqlite3_vfs*, sqlite3_int64*);

/*
** Forward declarations
*/
static CevfsMemPage *memPageFromDbPage(DbPage *pDbPage, Pgno mappedPgno);
static int cevfsNewDatabase(cevfs_file *pFile);
static int cevfsWriteUncompressed(cevfs_file *, Pgno, CevfsCmpOfst, const void *zBuf, int iAmt);
static int cevfsReadUncompressed(cevfs_file *, Pgno, CevfsCmpOfst, void *zBuf, int iAmt);
static int cevfsSaveHeader(cevfs_file *p);
static int cevfsLoadHeader(cevfs_file *p);

/*
** Return a pointer to the tail of the pathname.  Examples:
**
**     /home/drh/xyzzy.txt -> xyzzy.txt
**     xyzzy.txt           -> xyzzy.txt
*/
const char *fileTail(const char *z){
  int i;
  if( z==0 ) return 0;
  i = (int)strlen(z)-1;
  while( i>0 && z[i-1]!='/' ){ i--; }
  return &z[i];
}

/*
** Map the upper pager's journal file onto a different name.
** findCreateFileMode() in os_unix.c requires journal file to be in same directory
** and not have additional '-' in name. We'll just append "btree" to distinguish it from ours.
** Note: everything after the '-' must be alphanumeric only. No punctuation allowed
** or an assertion will be triggered in debug mode.
**
** If we always had a pointer to the associated cevfs_file when processing a journal filename then
** we could associate the renamed journal filename with the corresponding database filename and
** encapsulate the memory management. Since we cannot, we use bMustRelease to assist with memory management.
**
** pFile or bMustRelease must be NULL. Both cannot be NULL.
** If bMustRelease is true upon return, the newly created string must be freed by the caller.
** Use sqlite3_free to free memory.
*/
static char * cevfsMapPath(cevfs_file *pFile, const char *zName, bool *bMustRelease){
  // Only one of pFile or bMustRelease MUST be NULL.
  assert( !(pFile && bMustRelease) && (pFile || bMustRelease) );

  static const char *zTail = "btree";
  if (bMustRelease) *bMustRelease = false;
  if( strstr(zName, "-journal")==0 ){
    return (char *)zName;
  }
  char *zUppJournalPath = pFile ? pFile->zUppJournalPath : NULL;
  if( zUppJournalPath == NULL ){
    zUppJournalPath = sqlite3_malloc((int)(strlen(zName)+strlen(zTail))+1);
    *zUppJournalPath = '\0';
    strcat(zUppJournalPath, zName);
    strcat(zUppJournalPath, zTail);
    if(pFile)
      pFile->zUppJournalPath = zUppJournalPath;
    else
      if (bMustRelease) *bMustRelease = true;
  }
  return zUppJournalPath;
}

/*
** Send trace output defined by zFormat and subsequent arguments.
*/
static void cevfs_printf(
  cevfs_info *pInfo,
  const char *zFormat,
  ...
){
  va_list ap;
  char *zMsg;
  va_start(ap, zFormat);
  zMsg = sqlite3_vmprintf(zFormat, ap);
  va_end(ap);
  fputs(zMsg, stdout);
  sqlite3_free(zMsg);
}

/*
** Convert value rc into a string and print it using zFormat.  zFormat
** should have exactly one %s
*/
static void cevfs_print_errcode(
  cevfs_info *pInfo,
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
  CEVFS_PRINTF(pInfo, zFormat, zVal);
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

static int cevfsReadUncompressed(
  cevfs_file *p,
  Pgno pgno,
  CevfsCmpOfst offset,
  void *zBuf,
  int iAmt
){
  int rc;
  DbPage *pPage;
  if( (rc = sqlite3PagerGet(p->pPager, pgno, &pPage, 0)) == SQLITE_OK ){
    void *data = sqlite3PagerGetData(pPage);
    memcpy(zBuf, data+offset, iAmt);
    sqlite3PagerUnref(pPage);
  }
  return rc;
}

static void cevfsReleasePage1(cevfs_file *p){
  if( p->pPage1 ){
    sqlite3PagerUnref(p->pPage1->pDbPage);
    p->pPage1 = NULL;
  }
}

/*
** Create master mapping table.
** This table will point to the actual upper-to-lower page maps.
** Its size depends on the page size of the lower pager.
*/
static int cevfsCreateMMTbl(cevfs_file *p, int *memSzOut){
  u16 maxSz = p->pageSize - CEVFS_DB_HEADER_SIZE;
  u16 maxEntries = maxSz / sizeof(CevfsMMTblEntry);

  // At this point, header may already be loaded from persistent storage
  // so be careful modifying header values that could be needed elsewhere.
  p->cevfsHeader.mmTblMaxCnt = maxEntries;
  p->mmTblCurrIx = -1; // u16, so results in some large number to mean "not defined"

  // allocate
  int memSz = maxEntries*sizeof(CevfsMMTblEntry);
  if( !(p->mmTbl = sqlite3_malloc(memSz)) ) return SQLITE_NOMEM;

  // out param
  if( memSzOut ) *memSzOut = memSz;
  return SQLITE_OK;
}

static int cevfsSavePagemapData(cevfs_file *p){
  int rc = SQLITE_OK;
  if( p->bPgMapDirty ){
    Pgno pgno = p->mmTbl[p->mmTblCurrIx].lwrPgno;
    rc = cevfsWriteUncompressed(p, pgno, 0, p->pBigEndianPgMap, p->pgMapSz);
    if( rc==SQLITE_OK ) p->bPgMapDirty = 0;
  }
  return rc;
}

static int cevfsSaveMMTbl(cevfs_file *p){
  int rc;
  assert( p->bReadOnly==0 );
  cevfs_header *header = &p->cevfsHeader;
  int memSz = header->mmTblMaxCnt*sizeof(CevfsMMTblEntry);
  CevfsMMTblEntry *buf = sqlite3_malloc(memSz);
  if( buf ){
    for(u16 i=0; i<header->mmTblCurrCnt; i++){
      put2byte((u8 *)&buf[i].lwrPgno, p->mmTbl[i].lwrPgno);
    }
    if( (rc = cevfsWriteUncompressed(p, 1, CEVFS_DB_MMTBL_OFST, buf, memSz))==SQLITE_OK){
      sqlite3_free(buf);
      rc = cevfsSavePagemapData(p);
    }
  }else rc = SQLITE_NOMEM;
  return rc;
}

static int cevfsLoadPagemapData(cevfs_file *p, u16 ix){
  int rc;
  cevfs_header *header = &p->cevfsHeader;
  assert( p->bPgMapDirty==0 );
  assert( ix != p->mmTblCurrIx ); // mmTblCurrIx initially large number to mean no entries yet
  Pgno pgno = p->mmTbl[ix].lwrPgno;
  rc = cevfsReadUncompressed(p, pgno, 0, p->pBigEndianPgMap, p->pgMapSz);
  if( rc==SQLITE_OK ){
    u16 maxCnt = ix==header->mmTblCurrCnt-1 ? header->pgMapCnt : p->pgMapMaxCnt;
    for(u16 i = 0; i<maxCnt; i++){
      p->pPgMap[i].lwrPgno = get4byte((u8 *)&p->pBigEndianPgMap[i].lwrPgno);
      p->pPgMap[i].cmprSz = get2byte((u8 *)&p->pBigEndianPgMap[i].cmprSz);
      p->pPgMap[i].cmprOfst = get2byte((u8 *)&p->pBigEndianPgMap[i].cmprOfst);
    }
    p->mmTblCurrIx = ix;
  }
  return rc;
}

static int cevfsLoadMMTbl(cevfs_file *p){
  int rc;
  int memSz;
  cevfs_header *header = &p->cevfsHeader;
  assert( p->mmTbl==NULL );

  // Header must have already been loaded
  assert( header->mmTblCurrCnt>0 );

  if( (rc = cevfsCreateMMTbl(p, &memSz))==SQLITE_OK ){
    CevfsMMTblEntry *buf = sqlite3_malloc(memSz);
    if( buf ){
      if( (rc = cevfsReadUncompressed(p, 1, CEVFS_DB_MMTBL_OFST, buf, memSz))==SQLITE_OK){
        for(u16 i=0; i<header->mmTblCurrCnt; i++){
          p->mmTbl[i].lwrPgno = get2byte((u8 *)&buf[i].lwrPgno);
        }
        sqlite3_free(buf);
      }
    }
  }else rc = SQLITE_NOMEM;
  return rc;
}

static int cevfsPagerLock(cevfs_file *p){
  int rc;
  assert( p->pPage1==0 );
  if( (rc = sqlite3PagerSharedLock(p->pPager))==SQLITE_OK ){
    DbPage *pDbPage1;
    if( (rc = sqlite3PagerGet(p->pPager, 1, &pDbPage1, 0))==SQLITE_OK ){
      p->pPage1 = memPageFromDbPage(pDbPage1, 1);
      int nPageFile = 0;
      sqlite3PagerPagecount(p->pPager, &nPageFile);

      // calc max entries for each page map based on page size
      p->pgMapMaxCnt = p->pageSize / sizeof(cevfs_map_entry);
      p->pgMapSz = p->pgMapMaxCnt * sizeof(cevfs_map_entry);

      // Optimization: Do this multiplication and store it for later use.
      p->nBytesPerPgMap = p->pgMapMaxCnt * p->cevfsHeader.uppPgSz;

      /* Allocate space for a single page map.
       Only one page map will be in memory at a time. */
      p->pPgMap = sqlite3_malloc(p->pgMapSz);
      p->pBigEndianPgMap = sqlite3_malloc(p->pgMapSz);
      if( p->pPgMap && p->pBigEndianPgMap ){
        memset((void *)p->pPgMap, 0, p->pgMapSz);
        memset((void *)p->pBigEndianPgMap, 0, p->pgMapSz);
        if( nPageFile==0 ){
          /* We will be creating a new database so set up some data that is
           needed right away that would be too late to do in cevfsNewDatabase(). */
          if( (rc = cevfsCreateMMTbl(p, NULL))==SQLITE_OK ){
            p->mmTbl[0].lwrPgno = 2;
            p->cevfsHeader.mmTblCurrCnt = 1;
          }
        }else{
          // restore some data
          rc = cevfsLoadHeader(p);
          if( rc==SQLITE_OK && p->cevfsHeader.schema > CEVFS_FILE_SCHEMA_NO ){
            // The file schema# is larger than this version can handle.
            // A newer version is needed to read this file.
            rc = CEVFS_ERROR_EXT_VERSION_TOO_OLD;
          }
          if( rc==SQLITE_OK ) rc = cevfsLoadMMTbl(p);
          if( rc==SQLITE_OK ) rc = cevfsLoadPagemapData(p, 0);
        }
        /* reminder: do not call sqlite3PagerUnref(pDbPage1) here as this will
         cause pager state to reset to PAGER_OPEN which is not desirable for writing to pager. */
      }else rc = SQLITE_NOMEM;
    }
  }
  return rc;
}

static int cevfsPagerWrite(cevfs_file *p, PgHdr *pPg){
  int rc = SQLITE_OK;
  if( p->nTransactions == 0 ){
    if( (rc = sqlite3PagerBegin(p->pPager, 0, 1))==SQLITE_OK ){
      p->nTransactions++;
      if( p->lwrPageFile==0 ){
        rc = cevfsNewDatabase(p);
      }
    }
  }
  if( rc==SQLITE_OK ) return sqlite3PagerWrite(pPg);
  return rc;
}

static int cevfsWriteUncompressed(
  cevfs_file *pFile,
  Pgno pgno,
  CevfsCmpOfst offset,
  const void *zBuf,
  int iAmt
){
  int rc;
  DbPage *pPage = NULL;
  if( (rc = sqlite3PagerGet(pFile->pPager, pgno, &pPage, 0)) == SQLITE_OK ){
    void *data = sqlite3PagerGetData(pPage);
    if( (rc = cevfsPagerWrite(pFile, pPage)) == SQLITE_OK ){
      memcpy(data+offset, zBuf, iAmt);
    }
    sqlite3PagerUnref(pPage);
  }
  return rc;
}

static int cevfsSaveHeader(cevfs_file *p){
  assert( p->bReadOnly==0 );
  cevfs_header *header = &p->cevfsHeader;
  u8 buf[CEVFS_DB_HEADER2_SZ];
  memcpy(buf, &header->schema, 1);
  put4byte(buf+1, header->currPgno);
  put2byte(buf+5, header->currPageOfst);
  put2byte(buf+7, header->pgMapCnt);
  put4byte(buf+9, header->uppPgSz);
  put4byte(buf+13, header->uppPageFile);
  put2byte(buf+17, header->mmTblMaxCnt);
  put2byte(buf+19, header->mmTblCurrCnt);
  memset(buf+21, 0, 79);
  return cevfsWriteUncompressed(p, 1, CEVFS_DB_HEADER2_OFST, buf, CEVFS_DB_HEADER2_SZ);
}

static int cevfsLoadHeader(cevfs_file *p){
  cevfs_header *header = &p->cevfsHeader;
  u8 buf[CEVFS_DB_HEADER2_SZ];
  int rc;
  if( (rc = cevfsReadUncompressed(p, 1, CEVFS_DB_HEADER2_OFST, buf, CEVFS_DB_HEADER2_SZ))==SQLITE_OK ){
    header->schema = buf[0];
    header->currPgno = get4byte(buf+1);
    header->currPageOfst = get2byte(buf+5);
    header->pgMapCnt = get2byte(buf+7);
    header->uppPgSz = get4byte(buf+9);
    header->uppPageFile = get4byte(buf+13);
    header->mmTblMaxCnt = get2byte(buf+17);
    header->mmTblCurrCnt = get2byte(buf+19);
  }
  return rc;
}

static CevfsMemPage *memPageFromDbPage(DbPage *pDbPage, Pgno mappedPgno){
  CevfsMemPage* pPg = (CevfsMemPage *)sqlite3PagerGetExtra(pDbPage);
  if( mappedPgno != pPg->pgno  ){
    pPg->pgno = mappedPgno;
    pPg->pDbPage = pDbPage;
    pPg->dbHdrOffset = mappedPgno==1 ? CEVFS_DB_HEADER_SIZE : 0;
    pPg->pgHdrOffset = 0; // Not used anymore
    pPg->pDbPage->pgno = mappedPgno; // pager uses this to determine pager size
    pPg->aData = sqlite3PagerGetData(pDbPage);
  }
  return pPg;
}

static int cevfsNewDatabase(cevfs_file *pFile){
  CevfsMemPage *pP1 = pFile->pPage1;
  unsigned char *data = pP1->aData;
  cevfs_info *pInfo = (cevfs_info *)pFile->pInfo;
  int rc;

  if( (rc = cevfsPagerWrite(pFile, pP1->pDbPage))==SQLITE_OK ){
    // since we are using a secondary pager, set up a proper pager header (see btree.c:1898)

    // Set first 16 characters (including NULL terminator)
    // to the name of the VFS prefixed with CEVFS-
    // This leaves the user with 10 characters to identify the VFS.
    const char *prefix = "CEVFS-";
    const size_t iLen1 = strlen(prefix);
    const size_t iLen2 = 15-iLen1;
    const size_t iNameLen = strlen(pInfo->zVfsName);
    memset(data, 0, 16);
    memcpy(data, prefix, iLen1);
    memcpy(data+iLen1, pInfo->zVfsName, iNameLen > iLen2 ? iLen2 : iNameLen);
    assert( strlen((const char *)data)<16 );

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

/*
** Switch to a specific page map based on pager offset,
** saving the current page map if needed.
** @returns index# of page map switched to.
*/
static u16 cevfsSwitchPageMap(cevfs_file *p, sqlite_int64 iUppOfst){
  int rc = SQLITE_ERROR;
  cevfs_info *pInfo = p->pInfo;
  cevfs_header *header = &p->cevfsHeader;
  u16 ix = 0;

  /*
    Calculate map index based on upper pager offset.
    Check last entry first as an optimization in case we are writing.
    Perhaps we can do this check only when we are writing, skip for read-only.
  */
  ix = iUppOfst >= (p->nBytesPerPgMap * header->mmTblCurrCnt)
  ? header->mmTblCurrCnt-1
  : (u16)(iUppOfst / p->nBytesPerPgMap);
  if( ix<header->mmTblCurrCnt ) rc=SQLITE_OK;

  // switch
  if( rc==SQLITE_OK && ix != p->mmTblCurrIx ){
    CEVFS_PRINTF(pInfo, "Switching to map #%u for offset %lld\n", (unsigned)ix, iUppOfst);
    // save
    if( (rc = cevfsSavePagemapData(p))==SQLITE_OK ){
      // reset
      memset(p->pPgMap, 0, p->pgMapSz);
      //load
      rc = cevfsLoadPagemapData(p, ix);
      if( rc==SQLITE_OK ) p->mmTblCurrIx = ix;
    }
  }
  return ix;
}

static int cevfsPageMapGet(
  cevfs_file *pFile,
  sqlite_uint64 uSrcOfst,
  Pgno *outUppPgno,
  Pgno *outLwrPgno,
  CevfsCmpOfst *outCmpOfst,
  CevfsCmpSize *outCmpSz,
  u16 *outIx
){
  cevfs_header *header = &pFile->cevfsHeader;
  if( outUppPgno ) *outUppPgno = (Pgno)(uSrcOfst/header->uppPgSz+1);
  int currPgMapNo = cevfsSwitchPageMap(pFile, uSrcOfst);
  if( pFile->pPgMap ){
    // determine max elements based on if last page map is currently in memory
    u16 maxCnt = pFile->mmTblCurrIx==header->mmTblCurrCnt-1 ? header->pgMapCnt : pFile->pgMapMaxCnt;
    // determine which page map
    u16 pgMapIx = (u16)(uSrcOfst/pFile->nBytesPerPgMap);
    // determine index of entry on page map
    int ix = uSrcOfst % pFile->nBytesPerPgMap / header->uppPgSz;
    if(
      ix<maxCnt                 // if we reach or go beyond maxCnt, entry doesn't exist yet
      && pgMapIx==currPgMapNo   // if pgMap not yet created, entry doesn't exist yet
    ){
      if( outLwrPgno ) *outLwrPgno = pFile->pPgMap[ix].lwrPgno;
      if( outCmpSz ) *outCmpSz = pFile->pPgMap[ix].cmprSz;
      if( outCmpOfst ) *outCmpOfst = pFile->pPgMap[ix].cmprOfst;
      if( outIx ) *outIx = ix;
      return SQLITE_OK;
    }
  }
  return SQLITE_ERROR;
}

/*
** Allocate space to store a compressed page.
**
** "Allocate" here simply means to determine a page and offset
** within the lower pager where the data will be stored.
*/
void cevfsAllocCmpPageSpace(
  cevfs_file *pFile,
  CevfsCmpSize cmpSz,           // Current compressed size of data for allocation
  u16 pgMapIx                   // Index of map entry to record allocation data
){
  cevfs_header *header = &pFile->cevfsHeader;
  CevfsCmpOfst ofst = header->currPageOfst;
  cevfs_map_entry *pMapEntry = &pFile->pPgMap[pgMapIx];
  cevfs_map_entry *pBigEndianPgMapEntry = &pFile->pBigEndianPgMap[pgMapIx];
  // Since we no longer write compressed pages to page 1, we can optimize this
  //u32 realPageSize = pFile->pageSize - (header->currPgno == 1 ? CEVFS_DB_HEADER_SIZE : 0);
  header->currPageOfst += cmpSz;
  if( header->currPageOfst > /*realPageSize*/ pFile->pageSize ){
    // current page can't hold any more, start new page.
    ofst = 0;
    header->currPageOfst = cmpSz;
    // Make sure to not use a pgno that we allocated to a pagemap page.
    Pgno lstAllocatedPgMapPgno = pFile->mmTbl[header->mmTblCurrCnt-1].lwrPgno;
    if( header->currPgno <=  lstAllocatedPgMapPgno )
      header->currPgno = lstAllocatedPgMapPgno + 1;
    else
      header->currPgno++;
  }
  // Set data in map and in Big Endian version of map for fast save to persistent storage
  pMapEntry->lwrPgno = header->currPgno;
  pMapEntry->cmprOfst = ofst;
  pMapEntry->cmprSz = cmpSz;
  put4byte((u8 *)&pBigEndianPgMapEntry->lwrPgno, pMapEntry->lwrPgno);
  put2byte((u8 *)&pBigEndianPgMapEntry->cmprSz, pMapEntry->cmprSz);
  put2byte((u8 *)&pBigEndianPgMapEntry->cmprOfst, pMapEntry->cmprOfst);
  pFile->bPgMapDirty = 1;
}

int cevfsAddPageEntry(
  cevfs_file *pFile,
  sqlite3_int64 uppOfst,
  CevfsCmpSize cmpSz,
  CevfsCmpOfst *outCmpOfst,
  Pgno *outLwrPgno
){
  assert( (!outCmpOfst && !outLwrPgno) || (outCmpOfst && outLwrPgno) );
  cevfs_header *header = &pFile->cevfsHeader;

  // if no more room, start a new pagemap
  if( header->pgMapCnt == pFile->pgMapMaxCnt ){
    if( pFile->mmTblCurrIx == header->mmTblMaxCnt ){
      // We've run out of room in the master map table.
      // User will need to increase pager size.
      return CEVFS_ERROR_PAGE_SIZE_TOO_SMALL;
    }
    CevfsMMTblEntry *entry = &pFile->mmTbl[header->mmTblCurrCnt];
    entry->lwrPgno = header->currPgno+1; // use next pgno but don't incr. counter!
    header->mmTblCurrCnt++;
    header->pgMapCnt = 0;
    // reminder: can't change pInfo->mmTblCurrIx until after cevfsSwitchPageMap
    cevfsSwitchPageMap(pFile, uppOfst);
  }

  // add new page map entry
  u16 ix = header->pgMapCnt++;
  cevfs_map_entry *pPgMapEntry = &pFile->pPgMap[ix];

  // assign space to store compressed page
  cevfsAllocCmpPageSpace(pFile, cmpSz, ix);

  // for placeholder entries, set some data to zero
  if( !outLwrPgno ) pPgMapEntry->lwrPgno =  0;
  if( !outCmpOfst ) pPgMapEntry->cmprOfst = 0;

  // output params
  if( outLwrPgno ) *outLwrPgno = header->currPgno;
  if( outCmpOfst ) *outCmpOfst = pPgMapEntry->cmprOfst;

  return SQLITE_OK;
}

/*
** Add pager map entry before writing to lower pager
** to get pgno & offset for pager write operation.
**
** uppOfst - upper pager offset
** cmpSz - compressed size to save
** outLwrPgno - mapped pgno to write to
** outCmpOfst - offset to write compressed data to
**/
static int cevfsPageMapSet(
  cevfs_file *pFile,
  sqlite_int64 uppOfst,
  CevfsCmpSize cmpSz,
  Pgno *outUppPgno,
  Pgno *outLwrPgno,
  CevfsCmpOfst *outCmpOfst
){
  cevfs_info *pInfo = pFile->pInfo;
  cevfs_header *header = &pFile->cevfsHeader;
  CevfsCmpSize oldCmpSz;
  int rc = SQLITE_OK;
  u16 ix;

  assert( outUppPgno );
  assert( outLwrPgno );
  assert( outCmpOfst );

  if( (rc = cevfsPageMapGet(pFile, uppOfst, outUppPgno, outLwrPgno, outCmpOfst, &oldCmpSz, &ix))==SQLITE_OK ){
    /*
    ** We found a map entry. It's either a placeholder entry that needs valid data,
    ** an outdated entry that needs updating, or a valid up-to-date entry.
    ** If the entry needs updating, we will reuse the space used to hold the previously compressed
    ** data if the compressed data now takes up less space or allocate a new space at the end of
    ** the db if it now needs more space.
    ** Any previously used and now abandoned space will need to be recovered through a vacuum process.
    */
    if( oldCmpSz==0 || cmpSz>oldCmpSz ){
      // entry found was either a placeholder or we now need more room, so allocate new space.
      cevfs_map_entry *pMapEntry = &pFile->pPgMap[ix];
      cevfsAllocCmpPageSpace(pFile, cmpSz, ix);

      *outLwrPgno = pMapEntry->lwrPgno;
      *outCmpOfst = pMapEntry->cmprOfst;
      CEVFS_PRINTF(pInfo, "Updated entry (uppOfst=%lld, lwrPgno=%lu,cmpOfst=%lu,cmpSz=%lu)\n",
                   (long long)uppOfst, (unsigned long)pMapEntry->lwrPgno, (unsigned long)pMapEntry->cmprOfst, (unsigned long)pMapEntry->cmprSz);
      return SQLITE_OK;
    }else if( cmpSz<oldCmpSz ){
      // Update map entry data and keep compressed page slot. Abandoned space will need to be recovered via a vacuum operaion.
      pFile->pPgMap[ix].cmprSz = cmpSz;
      put2byte((u8 *)&pFile->pBigEndianPgMap[ix].cmprSz, cmpSz);
      pFile->bPgMapDirty = 1;
    }
    return rc;
  }else{
    sqlite3_int64 nextOfst = ((header->mmTblCurrCnt-1) * header->uppPgSz * pFile->pgMapMaxCnt) + (header->pgMapCnt * header->uppPgSz);
    while( uppOfst>nextOfst ){
      cevfsAddPageEntry(pFile, nextOfst, 0, NULL, NULL);
      CEVFS_PRINTF(pInfo, "Added intermin entry (uppOfst=%lld, lwrPgno=0,cmpOfst=0,cmpSz=0)\n", (long long)nextOfst);
      nextOfst += header->uppPgSz;
    }
    assert( uppOfst==nextOfst );
    cevfsAddPageEntry(pFile, uppOfst, cmpSz, outCmpOfst, outLwrPgno);
  }
  return SQLITE_OK;
}

/*
** Close a cevfs-file.
*/
static int cevfsClose(sqlite3_file *pFile){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  CEVFS_PRINTF(pInfo, "%s.xClose(%s)", pInfo->zVfsName, p->zFName);

  if( p->pPager ){
    if( !p->bReadOnly ){
      int nPageFile = 0;   /* Number of pages in the database file */
      sqlite3PagerPagecount(p->pPager, &nPageFile);
      assert( p->lwrPageFile==nPageFile );

      u8 buf[4];
      sqlite3Put4byte(buf, p->lwrPageFile);
      rc = cevfsWriteUncompressed(p, 1, 28, buf, 4);
      rc = cevfsSaveHeader(p);

      if( (rc = cevfsSaveMMTbl(p))==SQLITE_OK ){
        for(int i=0; i<p->nTransactions; i++){
          if( (rc = sqlite3PagerCommitPhaseOne(p->pPager, NULL, 0))==SQLITE_OK ){
            sqlite3PagerCommitPhaseTwo(p->pPager);
          }
        }
        p->nTransactions = 0;
      }
    }

    if( rc==SQLITE_OK ){
      cevfsReleasePage1(p);
      if( (rc = sqlite3PagerCloseShim(p->pPager, pInfo->pDb))==SQLITE_OK ){
        p->pPager = NULL;
        if( p->zUppJournalPath ){
          sqlite3_free(p->zUppJournalPath);
          p->zUppJournalPath = NULL;
        }
        if( p->mmTbl ){
          sqlite3_free(p->mmTbl);
          p->mmTbl = NULL;
        }
        if( p->pPgMap ){
          sqlite3_free(p->pPgMap);
          p->pPgMap = NULL;
        }
        if( p->pBigEndianPgMap ){
          sqlite3_free(p->pBigEndianPgMap);
          p->pBigEndianPgMap = NULL;
        }
      }
    }
  }

  if( (rc == SQLITE_OK) && ((rc = p->pReal->pMethods->xClose(p->pReal)) == SQLITE_OK) ){
    sqlite3_free((void*)p->base.pMethods);
    p->base.pMethods = NULL;
  }

  cevfs_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Read data from a cevfs-file.
*/
static int cevfsRead(
  sqlite3_file *pFile,
  void *zBuf,
  int iAmt,
  sqlite_int64 iOfst
){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  u32 uppPgSz = p->cevfsHeader.uppPgSz;
  int rc;

  if( p->pPager && p->pPage1 ){
    DbPage *pPage;
    Pgno uppPgno, mappedPgno;
    CevfsCmpOfst cmprPgOfst;
    CevfsCmpSize uCmpPgSz;

    if( (rc = cevfsPageMapGet(p, iOfst, &uppPgno, &mappedPgno, &cmprPgOfst, &uCmpPgSz, NULL)) == SQLITE_OK ){
      if( rc==SQLITE_OK &&
         (rc = sqlite3PagerGet(p->pPager, mappedPgno, &pPage, 0))==SQLITE_OK
      ){
        void *pDecBuf = NULL;
        void *pUncBuf = NULL;
        void *pDstData = NULL;

        CevfsMemPage *pMemPage = memPageFromDbPage(pPage, mappedPgno);
        CEVFS_PRINTF(
          pInfo, "%s.xRead(%s,pgno=%u->%u,ofst=%08lld->%u,amt=%d->%u)",
          pInfo->zVfsName, p->zFName, uppPgno, mappedPgno, iOfst, cmprPgOfst, iAmt, uCmpPgSz
        );
        assert( uCmpPgSz > 0 );

        size_t iDstAmt = uppPgSz;
        int bSuccess = 1;

        void *pSrcData =
          (char *)pMemPage->aData
          +pMemPage->dbHdrOffset
          +pMemPage->pgHdrOffset
          +cmprPgOfst;

        // src = dst, assuming no encryption or compression
        pDstData = pSrcData;

        if( p->bEncryptionEnabled ){
          // The IV is stored first followed by the enctypted data
          void *iv = pSrcData;

          pDecBuf = sqlite3_malloc(uCmpPgSz);
          if( pDecBuf ){
            void *srcData = iv+p->nEncIvSz;
            size_t nDataInSize = uCmpPgSz-p->nEncIvSz;
            size_t nFinalSz;

            bSuccess = p->vfsMethods.xDecrypt(
              pInfo->pCtx,
              srcData,                  // dataIn
              nDataInSize,              // data-in length
              iv,                       // IvIn
              pDecBuf,                  // dataOut; result is written here.
              uCmpPgSz,                 // The size of the dataOut buffer in bytes
              &nFinalSz                 // On successful return, the number of bytes written to dataOut.
            );

            if( bSuccess ){
              uCmpPgSz = nFinalSz;
              pSrcData = pDstData = pDecBuf;
            }else rc=CEVFS_ERROR_DECRYPTION_FAILED;
          }else rc=SQLITE_NOMEM;
        } // encryption

        if( p->bCompressionEnabled && bSuccess && bSuccess && rc==SQLITE_OK ){
          pUncBuf = sqlite3_malloc((int)iDstAmt);
          if( pUncBuf ){
            bSuccess = p->vfsMethods.xUncompress(pInfo->pCtx, pUncBuf, &iDstAmt, pSrcData, (int)uCmpPgSz);
            if( bSuccess ){
              assert( iDstAmt==uppPgSz );
              pDstData = pUncBuf;
            }else rc=CEVFS_ERROR_DECOMPRESSION_FAILED;
          }else rc=SQLITE_NOMEM;
        }

        if( bSuccess && rc==SQLITE_OK ){
          u16 uBufOfst = iOfst % uppPgSz;
          memcpy(zBuf, pDstData+uBufOfst, iAmt);
        }

        if( pDecBuf ) sqlite3_free( pDecBuf );
        if( pUncBuf ) sqlite3_free( pUncBuf );
        sqlite3PagerUnref(pPage);
      }
    }else{
      CEVFS_PRINTF(pInfo, "%s.xRead(%s,ofst=%08lld,amt=%d)", pInfo->zVfsName, p->zFName, iOfst, iAmt);
      memset(zBuf, 0, iAmt);
      rc = SQLITE_OK;
    }
  }else{
    CEVFS_PRINTF(pInfo, "%s.xRead(%s,ofst=%08lld,amt=%d)", pInfo->zVfsName, p->zFName, iOfst, iAmt);
    rc = p->pReal->pMethods->xRead(p->pReal, zBuf, iAmt, iOfst);
  }
  cevfs_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Write data to a cevfs-file.
*/
static int cevfsWrite(
  sqlite3_file *pFile,
  const void *zBuf,
  int iAmt,
  sqlite_int64 iOfst
){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;

  if( p->pPager ){
    if( p->bReadOnly ) rc = SQLITE_READONLY;
    else{
      void *pCmpBuf = NULL;
      void *pEncBuf = NULL;
      void *pSrcData = (void *)zBuf;
      size_t nSrcAmt = iAmt;
      int bSuccess = 1;

      if( p->bCompressionEnabled ){
        size_t nDest = p->vfsMethods.xCompressBound(pInfo->pCtx, nSrcAmt);
        pCmpBuf = sqlite3_malloc((int)nDest);
        if( pCmpBuf ){
          bSuccess = p->vfsMethods.xCompress(pInfo->pCtx, pCmpBuf, &nDest, pSrcData, nSrcAmt);
          if( bSuccess ){
            pSrcData = pCmpBuf;
            nSrcAmt = nDest;
          }
        }else rc=SQLITE_NOMEM;
      }

      if( p->bEncryptionEnabled && bSuccess ){
        size_t tmp_csz = 0;
        void *iv = sqlite3_malloc((int)p->nEncIvSz);
        if( iv ){
          bSuccess = p->vfsMethods.xEncrypt(
            pInfo->pCtx,
            pSrcData,      // dataIn
            nSrcAmt,       // data-in length
            iv,            // IV out
            &pEncBuf,      // dataOut; result is written here.
            &tmp_csz,      // On successful return, the number of bytes written to dataOut.
            sqlite3_malloc
          );
          if( bSuccess && pEncBuf ){
            // Join IV and pEncBuf. If IV is greater than pInfo->nEncIvSz, it will be truncated.
            void *pIvEncBuf = NULL;
            CevfsCmpSize uIvEncSz = p->nEncIvSz+tmp_csz;
            pIvEncBuf = sqlite3_realloc(iv, (int)(uIvEncSz));
            memcpy(pIvEncBuf+p->nEncIvSz, pEncBuf, tmp_csz);
            sqlite3_free(pEncBuf);
            pSrcData = pEncBuf = pIvEncBuf;
            nSrcAmt = uIvEncSz;
          }else rc=CEVFS_ERROR_ENCRYPTION_FAILED;
        }else rc=SQLITE_NOMEM;
      }

      // Make sure dest/lwr page size is large enough for incoming page of data
      assert( nSrcAmt <= p->pageSize );
      if( rc==SQLITE_OK ){
        if( nSrcAmt <= p->pageSize ){
          DbPage *pPage;
          Pgno uppPgno, mappedPgno;
          CevfsCmpOfst cmprPgOfst;

          cevfsPageMapSet(p, iOfst, nSrcAmt, &uppPgno, &mappedPgno, &cmprPgOfst);

          // write
          if( rc==SQLITE_OK && (rc = sqlite3PagerGet(p->pPager, mappedPgno, &pPage, 0))==SQLITE_OK ){
            CevfsMemPage *pMemPage = memPageFromDbPage(pPage, mappedPgno);
            if( rc==SQLITE_OK && (rc = cevfsPagerWrite(p, pPage))==SQLITE_OK ){
              CEVFS_PRINTF(
                pInfo,
                "%s.xWrite(%s, pgno=%u->%u, offset=%08lld->%06lu, amt=%06d->%06d)",
                pInfo->zVfsName, p->zFName,
                uppPgno, mappedPgno,
                iOfst, (unsigned long)(pMemPage->dbHdrOffset+pMemPage->pgHdrOffset+cmprPgOfst),
                iAmt, nSrcAmt
              );
              memcpy(
                pMemPage->aData
                +pMemPage->dbHdrOffset
                +pMemPage->pgHdrOffset
                +cmprPgOfst,
                pSrcData,
                nSrcAmt
              );

              // Keep track of sizes of upper and lower pagers
              if( p->cevfsHeader.uppPageFile<uppPgno ) p->cevfsHeader.uppPageFile = uppPgno;
              if( p->lwrPageFile<mappedPgno ) p->lwrPageFile = mappedPgno;
            }
            sqlite3PagerUnref(pPage);
          }
        }else rc=CEVFS_ERROR_PAGE_SIZE_TOO_SMALL;
      }

      if( pEncBuf ) sqlite3_free( pEncBuf );
      if( pCmpBuf ) sqlite3_free( pCmpBuf );
    }
  }else{
    CEVFS_PRINTF(pInfo, "%s.xWrite(%s, offset=%08lld, amt=%06d)", pInfo->zVfsName, p->zFName, iOfst, iAmt);
    rc = p->pReal->pMethods->xWrite(p->pReal, zBuf, iAmt, iOfst);
  }
  cevfs_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Truncate a cevfs-file.
*/
static int cevfsTruncate(sqlite3_file *pFile, sqlite_int64 size){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  int rc;
  CEVFS_PRINTF(pInfo, "%s.xTruncate(%s,%lld)", pInfo->zVfsName, p->zFName, size);
  rc = p->pReal->pMethods->xTruncate(p->pReal, size);
  CEVFS_PRINTF(pInfo, " -> %d\n", rc);
  return rc;
}

/*
** Sync a cevfs-file.
*/
static int cevfsSync(sqlite3_file *pFile, int flags){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
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
  CEVFS_PRINTF(pInfo, "%s.xSync(%s,%s)", pInfo->zVfsName, p->zFName, &zBuf[1]);
  rc = p->pReal->pMethods->xSync(p->pReal, flags);
  CEVFS_PRINTF(pInfo, " -> %d\n", rc);
  return rc;
}

/*
** Return ficticious uncompressed file size based on number of pages from source pager
** otherwise internal checks in pager.c will fail.
*/
static int cevfsFileSize(sqlite3_file *pFile, sqlite_int64 *pSize){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  cevfs_header *header = &p->cevfsHeader;
  int rc;
  CEVFS_PRINTF(pInfo, "%s.xFileSize(%s)", pInfo->zVfsName, p->zFName);
  if( p->pPager ){
    *pSize = header->uppPageFile * header->uppPgSz;
    rc = SQLITE_OK;
  }else{
    rc = p->pReal->pMethods->xFileSize(p->pReal, pSize);
  }
  cevfs_print_errcode(pInfo, " -> %s,", rc);
  CEVFS_PRINTF(pInfo, " size=%lld\n", *pSize);
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
** Lock a cevfs-file.
** Never lock database file for upper pager as it doesn't directly control database file anymore.
*/
static int cevfsLock(sqlite3_file *pFile, int eLock){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  CEVFS_PRINTF(pInfo, "%s.xLock(%s,%s) BYPASS", pInfo->zVfsName, p->zFName, lockName(eLock));
  cevfs_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Unlock a cevfs-file.
** Never unlock database file for upper pager as it doesn't directly control database file anymore.
*/
static int cevfsUnlock(sqlite3_file *pFile, int eLock){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  CEVFS_PRINTF(pInfo, "%s.xUnlock(%s,%s) BYPASS", pInfo->zVfsName, p->zFName, lockName(eLock));
  cevfs_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Check if another file-handle holds a RESERVED lock on a cevfs-file.
** Bypass checks here since upper pager doesn't directly control database file anymore.
*/
static int cevfsCheckReservedLock(sqlite3_file *pFile, int *pResOut){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  *pResOut = 0; // not locked
  CEVFS_PRINTF(pInfo, "%s.xCheckReservedLock(%s,%d) BYPASS", pInfo->zVfsName, p->zFName);
  cevfs_print_errcode(pInfo, " -> %s", rc);
  CEVFS_PRINTF(pInfo, ", out=%d\n", *pResOut);
  CEVFS_PRINTF(pInfo, "\n");
  return rc;
}

static int cevfsPragma(sqlite3_file *pFile, const char *op, const char *arg){
  cevfs_file *p = (cevfs_file *)pFile;
  int rc = SQLITE_OK;
  if( strcmp(op, "page_size")==0 ){
    p->cevfsHeader.uppPgSz = (u32)sqlite3Atoi(arg);
  }
  return rc;
}

/*
** File control method. For custom operations on a cevfs-file.
*/
static int cevfsFileControl(sqlite3_file *pFile, int op, void *pArg){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  int rc;
  char zBuf[100];
  char *zOp;
  switch( op ){
#ifdef SQLITE_DEBUG
    case SQLITE_FCNTL_LOCKSTATE:    zOp = "LOCKSTATE";          break;
    case SQLITE_GET_LOCKPROXYFILE:  zOp = "GET_LOCKPROXYFILE";  break;
    case SQLITE_SET_LOCKPROXYFILE:  zOp = "SET_LOCKPROXYFILE";  break;
    case SQLITE_LAST_ERRNO:         zOp = "LAST_ERRNO";         break;
    case SQLITE_FCNTL_SIZE_HINT: {
      sqlite3_snprintf(sizeof(zBuf), zBuf, "SIZE_HINT,%lld", *(sqlite3_int64*)pArg);
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
    case SQLITE_FCNTL_MMAP_SIZE: {
      sqlite3_snprintf(sizeof(zBuf), zBuf, "SQLITE_FCNTL_MMAP_SIZE,%d", *(int*)pArg);
      zOp = zBuf;
      break;
    }
#endif
    case SQLITE_FCNTL_PRAGMA: {
      const char *const* a = (const char*const*)pArg;
      sqlite3_snprintf(sizeof(zBuf), zBuf, "PRAGMA,[%s,%s]",a[1],a[2]);
      zOp = zBuf;
      cevfsPragma(pFile, a[1], a[2]);
      break;
    }
    default: {
#ifdef SQLITE_DEBUG
      sqlite3_snprintf(sizeof(zBuf), zBuf, "%d", op);
      zOp = zBuf;
#endif
      break;
    }
  }
  CEVFS_PRINTF(pInfo, "%s.xFileControl(%s,%s)", pInfo->zVfsName, p->zFName, zOp);
  rc = p->pReal->pMethods->xFileControl(p->pReal, op, pArg);
  cevfs_print_errcode(pInfo, " -> %s\n", rc);

  if( op==SQLITE_FCNTL_VFSNAME && rc==SQLITE_OK ){
    *(char**)pArg = sqlite3_mprintf("cevfs.%s/%z", pInfo->zVfsName, *(char**)pArg);
  }

  if( (op==SQLITE_FCNTL_PRAGMA || op==SQLITE_FCNTL_TEMPFILENAME)
     && rc==SQLITE_OK && *(char**)pArg ){
    CEVFS_PRINTF(pInfo, "%s.xFileControl(%s,%s) returns %s", pInfo->zVfsName, p->zFName, zOp, *(char**)pArg);
  }
  return rc;
}

/*
** Return the sector-size in bytes for a cevfs-file.
*/
static int cevfsSectorSize(sqlite3_file *pFile){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  int rc;
  CEVFS_PRINTF(pInfo, "%s.xSectorSize(%s)", pInfo->zVfsName, p->zFName);
  rc = p->pReal->pMethods->xSectorSize(p->pReal);
  CEVFS_PRINTF(pInfo, " -> %d\n", rc);
  return rc;
}

/*
** Return the device characteristic flags supported by a cevfs-file.
*/
static int cevfsDeviceCharacteristics(sqlite3_file *pFile){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  int rc;
  CEVFS_PRINTF(pInfo, "%s.xDeviceCharacteristics(%s)", pInfo->zVfsName, p->zFName);
  rc = p->pReal->pMethods->xDeviceCharacteristics(p->pReal);
  CEVFS_PRINTF(pInfo, " -> 0x%08x\n", rc);
  return rc;
}

/*
** Shared-memory operations.
*/
static int cevfsShmLock(sqlite3_file *pFile, int ofst, int n, int flags){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
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
  CEVFS_PRINTF(pInfo, "%s.xShmLock(%s,ofst=%d,n=%d,%s)", pInfo->zVfsName, p->zFName, ofst, n, &zLck[1]);
  rc = p->pReal->pMethods->xShmLock(p->pReal, ofst, n, flags);
  cevfs_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}
static int cevfsShmMap(
  sqlite3_file *pFile,
  int iRegion,
  int szRegion,
  int isWrite,
  void volatile **pp
){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  int rc;
  CEVFS_PRINTF(pInfo, "%s.xShmMap(%s,iRegion=%d,szRegion=%d,isWrite=%d,*)", pInfo->zVfsName, p->zFName, iRegion, szRegion, isWrite);
  rc = p->pReal->pMethods->xShmMap(p->pReal, iRegion, szRegion, isWrite, pp);
  cevfs_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}
static void cevfsShmBarrier(sqlite3_file *pFile){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  CEVFS_PRINTF(pInfo, "%s.xShmBarrier(%s)\n", pInfo->zVfsName, p->zFName);
  p->pReal->pMethods->xShmBarrier(p->pReal);
}
static int cevfsShmUnmap(sqlite3_file *pFile, int delFlag){
  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = p->pInfo;
  int rc;
  CEVFS_PRINTF(pInfo, "%s.xShmUnmap(%s,delFlag=%d)", pInfo->zVfsName, p->zFName, delFlag);
  rc = p->pReal->pMethods->xShmUnmap(p->pReal, delFlag);
  cevfs_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}


static void cevfsPageReinit(DbPage *pData){

}

/*
** Open a cevfs file handle.
*/
static int cevfsOpen(
  sqlite3_vfs *pVfs,
  const char *_zName,
  sqlite3_file *pFile,
  int flags,
  int *pOutFlags
){
  // TODO: check to make sure db is not already open.

  u8 nReserve;
  int rc;

  cevfs_file *p = (cevfs_file *)pFile;
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  u32 nParamBlockSz = 0;

  // Zero-initialize
  int offset = sizeof(p->base)+sizeof(*(p->pReal));
  int size = sizeof(*p)-offset;
  memset((void*)p + offset, 0, size);

  // Initialize
  p->pInfo = pInfo;
  const char *zName = cevfsMapPath(p, _zName, NULL);
  p->zFName = zName ? fileTail(zName) : "<temp>";
  p->pReal = (sqlite3_file *)&p[1];
  p->cevfsHeader.schema = CEVFS_FILE_SCHEMA_NO;
  p->cevfsHeader.currPgno = CEVFS_FIRST_MAPPED_PAGE;

  // Set upper page size from temp storage else use default
  p->cevfsHeader.uppPgSz = pInfo->upperPgSize ? pInfo->upperPgSize : SQLITE_DEFAULT_PAGE_SIZE;

  // We need this for import
  pInfo->pFile = p;

  // Set readonly flag
  if( pInfo->cerod_activated && strcmp(pInfo->zVfsName, "cevfs-cerod")==0 ){
    p->bReadOnly = 1;
  }else if( flags & SQLITE_OPEN_READONLY ){
    p->bReadOnly = 1;
  }

  // Process URI parameters
  if( flags & SQLITE_OPEN_URI ){
    // block_size
    const char *zParamBlockSize = sqlite3_uri_parameter(_zName, "block_size");
    if( zParamBlockSize ) nParamBlockSz = (u32)sqlite3Atoi(zParamBlockSize);
  }

  // open file
  rc = pRoot->xOpen(pRoot, zName, p->pReal, flags, pOutFlags);
  CEVFS_PRINTF(pInfo, "%s.xOpen(%s,flags=0x%x)",pInfo->zVfsName, p->zFName, flags);

  if( rc==SQLITE_OK ){
    // hook up I/O methods
    if( p->pReal->pMethods ){
      sqlite3_io_methods *pNew = sqlite3_malloc( sizeof(*pNew) );
      const sqlite3_io_methods *pSub = p->pReal->pMethods;
      memset(pNew, 0, sizeof(*pNew));
      pNew->iVersion = pSub->iVersion;
      pNew->xClose = cevfsClose;
      pNew->xRead = cevfsRead;
      pNew->xWrite = cevfsWrite;
      pNew->xTruncate = cevfsTruncate;
      pNew->xSync = cevfsSync;
      pNew->xFileSize = cevfsFileSize;
      pNew->xLock = cevfsLock;
      pNew->xUnlock = cevfsUnlock;
      pNew->xCheckReservedLock = cevfsCheckReservedLock;
      pNew->xFileControl = cevfsFileControl;
      pNew->xSectorSize = cevfsSectorSize;
      pNew->xDeviceCharacteristics = cevfsDeviceCharacteristics;
      if( pNew->iVersion>=2 ){
        pNew->xShmMap = pSub->xShmMap ? cevfsShmMap : 0;
        pNew->xShmLock = pSub->xShmLock ? cevfsShmLock : 0;
        pNew->xShmBarrier = pSub->xShmBarrier ? cevfsShmBarrier : 0;
        pNew->xShmUnmap = pSub->xShmUnmap ? cevfsShmUnmap : 0;
      }
      pFile->pMethods = pNew;
    }

    // create pager to handle I/O to compressed/encrypted underlying db
    if( flags & (SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TRANSIENT_DB) ){
      if( (rc = sqlite3PagerOpen(pInfo->pRootVfs, &p->pPager, zName, EXTRA_SIZE, 0, flags, cevfsPageReinit))==SQLITE_OK){
        if( rc==SQLITE_OK ){
          sqlite3PagerSetJournalMode(p->pPager, PAGER_JOURNALMODE_DELETE);
//          sqlite3PagerJournalSizeLimit(p->pPager, -1);
//          rc = sqlite3PagerLockingMode(p->pPager, PAGER_LOCKINGMODE_NORMAL);
//          sqlite3PagerSetMmapLimit(pBt->pPager, db->szMmap); /* advisory, except if 0 */
          if( (rc = sqlite3PagerReadFileheader(p->pPager,sizeof(p->zDbHeader),p->zDbHeader)) == SQLITE_OK ){
            p->pageSize = (p->zDbHeader[16]<<8) | (p->zDbHeader[17]<<16);
            if( p->pageSize<512 || p->pageSize>SQLITE_MAX_PAGE_SIZE
               || ((p->pageSize-1)&p->pageSize)!=0 ){
              p->pageSize = nParamBlockSz; // if 0, sqlite3PagerSetPagesize will set page size
              nReserve = 0;
            }else{
              nReserve = p->zDbHeader[20];
              p->lwrPageFile = sqlite3Get4byte(p->zDbHeader+28);
            }
            sqlite3PagerSetMmapLimit(p->pPager, 0);
            if( (rc = sqlite3PagerSetPagesize(p->pPager, &p->pageSize, nReserve)) == SQLITE_OK ){
              p->usableSize = p->pageSize - nReserve;
              sqlite3PagerSetCachesize(p->pPager, SQLITE_DEFAULT_CACHE_SIZE);
              rc = cevfsPagerLock(p);
            }

            // Call user xAutoDetect to set up VFS methods
            if (pInfo->xAutoDetect) {
              pInfo->xAutoDetect(pInfo->pCtx, _zName, (const char *)p->zDbHeader+6, &p->nEncIvSz, &p->vfsMethods);
              if (p->vfsMethods.xCompressBound && p->vfsMethods.xCompress && p->vfsMethods.xUncompress)
                p->bCompressionEnabled = true;
              if (p->vfsMethods.xEncrypt && p->vfsMethods.xDecrypt)
                p->bEncryptionEnabled = true;
            }
          }
        }else{
          cevfsClose(pFile);
        }
      }
    }
  }

  cevfs_print_errcode(pInfo, " -> %s", rc);
  if( pOutFlags ){
    CEVFS_PRINTF(pInfo, ", outFlags=0x%x\n", *pOutFlags);
  }else{
    CEVFS_PRINTF(pInfo, "\n");
  }
  return rc;
}

/*
** Delete the file located at zPath. If the dirSync argument is true,
** ensure the file-system modifications are synced to disk before
** returning.
*/
static int cevfsDelete(sqlite3_vfs *pVfs, const char *_zPath, int dirSync){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  int rc;
  bool bMustRelease;

  char *zPath = cevfsMapPath(NULL, _zPath, &bMustRelease);
  CEVFS_PRINTF(pInfo, "%s.xDelete(\"%s\",%d)", pInfo->zVfsName, zPath, dirSync);
  rc = pRoot->xDelete(pRoot, zPath, dirSync);
  cevfs_print_errcode(pInfo, " -> %s\n", rc);
  if (bMustRelease)sqlite3_free(zPath);
  return rc;
}

/*
** Test for access permissions.
** Return true via *pResOut if the requested permission
** is available, or false otherwise.
*/
static int cevfsAccess(
  sqlite3_vfs *pVfs,
  const char *_zPath,
  int flags,
  int *pResOut
){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  bool bMustRelease;
  char *zPath = cevfsMapPath(NULL, _zPath, &bMustRelease);
  int rc = SQLITE_OK;

  CEVFS_PRINTF(pInfo, "%s.xAccess(\"%s\",%d)", pInfo->zVfsName, zPath, flags);
  rc = pRoot->xAccess(pRoot, zPath, flags, pResOut);
  cevfs_print_errcode(pInfo, " -> %s", rc);
  CEVFS_PRINTF(pInfo, ", out=%d\n", *pResOut);
  if (bMustRelease) sqlite3_free(zPath);
  return rc;
}

/*
** Populate buffer zOut with the full canonical pathname corresponding
** to the pathname in zPath. zOut is guaranteed to point to a buffer
** of at least (DEVSYM_MAX_PATHNAME+1) bytes.
*/
static int cevfsFullPathname(
  sqlite3_vfs *pVfs,
  const char *zPath,
  int nOut,
  char *zOut
){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  int rc;
  CEVFS_PRINTF(pInfo, "%s.xFullPathname(\"%s\")", pInfo->zVfsName, zPath);
  rc = pRoot->xFullPathname(pRoot, zPath, nOut, zOut);
  cevfs_print_errcode(pInfo, " -> %s", rc);
  CEVFS_PRINTF(pInfo, ", out=\"%.*s\"\n", nOut, zOut);
  return rc;
}

/*
** Open the dynamic library located at zPath and return a handle.
*/
static void *cevfsDlOpen(sqlite3_vfs *pVfs, const char *zPath){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  CEVFS_PRINTF(pInfo, "%s.xDlOpen(\"%s\")\n", pInfo->zVfsName, zPath);
  return pRoot->xDlOpen(pRoot, zPath);
}

/*
** Populate the buffer zErrMsg (size nByte bytes) with a human readable
** utf-8 string describing the most recent error encountered associated
** with dynamic libraries.
*/
static void cevfsDlError(sqlite3_vfs *pVfs, int nByte, char *zErrMsg){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  CEVFS_PRINTF(pInfo, "%s.xDlError(%d)", pInfo->zVfsName, nByte);
  pRoot->xDlError(pRoot, nByte, zErrMsg);
  CEVFS_PRINTF(pInfo, " -> \"%s\"", zErrMsg);
}

/*
** Return a pointer to the symbol zSymbol in the dynamic library pHandle.
*/
static void (*cevfsDlSym(sqlite3_vfs *pVfs,void *p,const char *zSym))(void){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  CEVFS_PRINTF(pInfo, "%s.xDlSym(\"%s\")\n", pInfo->zVfsName, zSym);
  return pRoot->xDlSym(pRoot, p, zSym);
}

/*
** Close the dynamic library handle pHandle.
*/
static void cevfsDlClose(sqlite3_vfs *pVfs, void *pHandle){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  CEVFS_PRINTF(pInfo, "%s.xDlOpen()\n", pInfo->zVfsName);
  pRoot->xDlClose(pRoot, pHandle);
}

/*
** Populate the buffer pointed to by zBufOut with nByte bytes of
** random data.
*/
static int cevfsRandomness(sqlite3_vfs *pVfs, int nByte, char *zBufOut){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  CEVFS_PRINTF(pInfo, "%s.xRandomness(%d)\n", pInfo->zVfsName, nByte);
  return pRoot->xRandomness(pRoot, nByte, zBufOut);
}

/*
** Sleep for nMicro microseconds. Return the number of microseconds
** actually slept.
*/
static int cevfsSleep(sqlite3_vfs *pVfs, int nMicro){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xSleep(pRoot, nMicro);
}

/*
** Return the current time as a Julian Day number in *pTimeOut.
*/
static int cevfsCurrentTime(sqlite3_vfs *pVfs, double *pTimeOut){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xCurrentTime(pRoot, pTimeOut);
}
static int cevfsCurrentTimeInt64(sqlite3_vfs *pVfs, sqlite3_int64 *pTimeOut){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xCurrentTimeInt64(pRoot, pTimeOut);
}

/*
** Return the emost recent error code and message
*/
static int cevfsGetLastError(sqlite3_vfs *pVfs, int iErr, char *zErr){
  cevfs_info *pInfo = (cevfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xGetLastError(pRoot, iErr, zErr);
}

/*
** Clients invoke cevfs_create_vfs to construct a new cevfs.
**
** Return SQLITE_OK on success.
**
** SQLITE_NOMEM is returned in the case of a memory allocation error.
** SQLITE_NOTFOUND is returned if zOldVfsName does not exist.
*/
int cevfs_create_vfs(
  char const *zName,         // Name of the newly constructed VFS.
  char const *zParent,       // Name of the underlying VFS. NULL to use default.
  void *pCtx,                // Context pointer to be passed to CEVFS methods.
  t_xAutoDetect xAutoDetect, // Pointer to xAutoDetect custom supplied function.
  int makeDefault
){
  sqlite3_vfs *pNew;
  sqlite3_vfs *pRoot;
  cevfs_info *pInfo;
  int nName;
  int nByte;

  // Allow parameters to be passed with database filename in URI form.
  sqlite3_config(SQLITE_CONFIG_URI, 1);

  // Don't register VFS with same name more than once
  if( sqlite3_vfs_find(zName) )
    return CEVFS_ERROR_VFS_ALREADY_EXISTS;

  pRoot = sqlite3_vfs_find(zParent);
  if( pRoot==0 ) return SQLITE_NOTFOUND;
  nName = (int)strlen(zName);

  // Allocate memory for a new sqlite3_vfs, cevfs_info and the name of the new VFS.
  nByte = sizeof(*pNew) + sizeof(*pInfo) + nName + 1;
  pNew = sqlite3_malloc( nByte );
  if( pNew==0 ) return SQLITE_NOMEM;
  memset(pNew, 0, nByte);

  // Hook up the rest of the allocated memory
  pInfo = (cevfs_info*)&pNew[1];
  pNew->zName = (char*)&pInfo[1];

  // Intialize data
  memcpy((char*)&pInfo[1], zName, nName+1);
  pNew->iVersion = pRoot->iVersion;
  pNew->szOsFile = pRoot->szOsFile + sizeof(cevfs_file);
  pNew->mxPathname = pRoot->mxPathname;
  pNew->pAppData = pInfo;
  pNew->xOpen = cevfsOpen;
  pNew->xDelete = cevfsDelete;
  pNew->xAccess = cevfsAccess;
  pNew->xFullPathname = cevfsFullPathname;
  pNew->xDlOpen = pRoot->xDlOpen==0 ? 0 : cevfsDlOpen;
  pNew->xDlError = pRoot->xDlError==0 ? 0 : cevfsDlError;
  pNew->xDlSym = pRoot->xDlSym==0 ? 0 : cevfsDlSym;
  pNew->xDlClose = pRoot->xDlClose==0 ? 0 : cevfsDlClose;
  pNew->xRandomness = cevfsRandomness;
  pNew->xSleep = cevfsSleep;
  pNew->xCurrentTime = cevfsCurrentTime;
  pNew->xGetLastError = pRoot->xGetLastError==0 ? 0 : cevfsGetLastError;
  if( pNew->iVersion>=2 ){
    pNew->xCurrentTimeInt64 = pRoot->xCurrentTimeInt64==0 ? 0 : cevfsCurrentTimeInt64;
    if( pNew->iVersion>=3 ){
      pNew->xSetSystemCall = 0;
      pNew->xGetSystemCall = 0;
      pNew->xNextSystemCall = 0;
    }
  }
  pInfo->pRootVfs = pRoot;
  pInfo->zVfsName = pNew->zName;
  pInfo->pCevfsVfs = pNew;
  pInfo->pCtx = pCtx;
  pInfo->xAutoDetect = xAutoDetect;

  CEVFS_PRINTF(pInfo, "%s.enabled_for(\"%s\")\n", pInfo->zVfsName, pRoot->zName);
  return sqlite3_vfs_register(pNew, makeDefault);
}

static int _cevfs_destroy_vfs(sqlite3_vfs *pVfs) {
  sqlite3_free(pVfs);
  return SQLITE_OK;
}

int cevfs_destroy_vfs(const char *zName){
  sqlite3_vfs *pVfs = sqlite3_vfs_find(zName);
  if( pVfs ){
    //cevfs_info *pInfo = (cevfs_info *)pVfs->pAppData;
    return _cevfs_destroy_vfs(pVfs);
  }
  return CEVFS_ERROR_VFS_DOES_NOT_EXIST;
}

int cevfs_build(
  const char *zSrcFilename,
  const char *zDestFilename,
  const char *vfsName,
  void *pCtx,
  t_xAutoDetect xAutoDetect
){
  int rc = SQLITE_OK;
  unsigned char zDbHeader[100];
  sqlite3_vfs *pDestVfs = NULL;

  // cevfs_create_vfs must be done early enough to avoid SQLITE_MISUSE error
  rc = cevfs_create_vfs(vfsName, NULL, pCtx, xAutoDetect, 0);
  if( rc==SQLITE_OK || rc==CEVFS_ERROR_VFS_ALREADY_EXISTS ){
    pDestVfs = sqlite3_vfs_find(vfsName);
  }

  if( pDestVfs ){
    sqlite3_vfs *pSrcVfs = sqlite3_vfs_find(NULL);
    if( pSrcVfs ){
      Pager *pPager;
      int vfsFlags = SQLITE_OPEN_READONLY | SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_URI;
      if( (rc = sqlite3PagerOpen(pSrcVfs, &pPager, zSrcFilename, EXTRA_SIZE, 0, vfsFlags, cevfsPageReinit))==SQLITE_OK ){
        sqlite3PagerSetJournalMode(pPager, PAGER_JOURNALMODE_OFF);
        if( (rc = sqlite3PagerReadFileheader(pPager,sizeof(zDbHeader),zDbHeader)) == SQLITE_OK ){
          u32 pageSize = (zDbHeader[16]<<8) | (zDbHeader[17]<<16);
          if( pageSize>=512 && pageSize<=SQLITE_MAX_PAGE_SIZE  // validate range
             && ((pageSize-1)&pageSize)==0 ){                  // validate page size is a power of 2
            u8 nReserve = zDbHeader[20];
            if( (rc = sqlite3PagerSetPagesize(pPager, &pageSize, nReserve)) == SQLITE_OK ){
              u32 fileChangeCounter = sqlite3Get4byte(zDbHeader+24);
              u32 pageCount = sqlite3Get4byte(zDbHeader+28);
              u32 versionValidForNumber = sqlite3Get4byte(zDbHeader+92);

              // If we didn't get page count, figure it out from the file size
              if( !(pageCount>0 && fileChangeCounter==versionValidForNumber) ){
                struct stat st;
                if( stat(zSrcFilename, &st)==0 ){
                  off_t size = st.st_size;
                  pageCount = (u32)(size/pageSize);
                }
              }

              // lock pager, prepare to read
              if( rc==SQLITE_OK && (rc = sqlite3PagerSharedLock(pPager))==SQLITE_OK ){
                // get destination ready to receive data
                sqlite3 *pDb;

                // Must set upper page size before sqlite3_open_v2
                // as cevfsOpen will be invoked and expecting this value.
                cevfs_info *pInfo = (cevfs_info *)pDestVfs->pAppData;
                pInfo->upperPgSize = pageSize;

                if( (rc = sqlite3_open_v2(zDestFilename, &pDb, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, vfsName))==SQLITE_OK ){
                 // Needed for sqlite3 API shims
                 pInfo->pDb = pDb;

                  DbPage *pPage1 = NULL;
                  // import all pages
                  for(Pgno pgno=0; pgno<pageCount; pgno++){
                    // read source page
                    DbPage *pPage;
                    rc = sqlite3PagerGet(pPager, pgno+1, &pPage, /* flags */ 0);
                    if( rc==SQLITE_OK ){
                      // read source page
                      void *pData = sqlite3PagerGetData(pPage);
                      // write destination page
                      rc = cevfsWrite((sqlite3_file *)pInfo->pFile, pData, pageSize, pageSize*pgno);
                      if( pgno==0 ){
                        // To be deallocated later
                        pPage1 = pPage;
                      }else{
                        sqlite3PagerUnref(pPage);
                      }
                      if( rc != SQLITE_OK ) break;
                    }else{
                      break;
                    }
                  }
                  if (pPage1) sqlite3PagerUnref(pPage1);
                  sqlite3PagerCloseShim(pPager, pDb);
                  rc = sqlite3_close(pDb);
                }
              }
            }
          } else rc = SQLITE_CORRUPT;
        }
      }
    } else rc = SQLITE_INTERNAL;
    _cevfs_destroy_vfs(pDestVfs);
  }
  return rc;
}
