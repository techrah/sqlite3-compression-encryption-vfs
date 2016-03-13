/*
 Compression & Encryption Shim VFS
*/
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"
#include "sqliteInt.h"
#include "pager.h"
#include "btreeInt.h"

// Size of standard Sqlite3 pager header
#define CESHIM_DB_HEADER1_SZ        100
// Size of ceshim-specific pager header
#define CESHIM_DB_HEADER2_SZ        100
#define CESHIM_DB_HEADER1_OFST      000
#define CESHIM_DB_HEADER2_OFST      CESHIM_DB_HEADER1_OFST+CESHIM_DB_HEADER1_SZ
// Offset to master map table
#define CESHIM_DB_MMTBL_OFST        CESHIM_DB_HEADER2_OFST+CESHIM_DB_HEADER2_SZ
#define CESHIM_DB_HEADER_SIZE       (CESHIM_DB_HEADER1_SZ + CESHIM_DB_HEADER2_SZ)

#define CESHIM_FILE_SCHEMA_NO         1
#define CESHIM_FIRST_MAPPED_PAGE      3

typedef u16 CeshimCompressedSize;
typedef u16 CeshimCompressedOffset;

/*
** The header string that appears at the beginning of every
** SQLite database.
*/
static const char zMagicHeader[] = SQLITE_FILE_HEADER;

/*
** Keeps track of data we need to persist for the pager.
** This will be stored uncompressed at offset 100-199.
*/
typedef struct ceshim_header ceshim_header;
struct ceshim_header {
  u8 schema;                            // 01 file schema version number
  Pgno currPgno;                        // 04 curr lower pager pgno being filled
  CeshimCompressedOffset currPageOfst;  // 02 curr offset for next compressed page
  u16 pgMapCnt;                         // 02 num elements of last page map
  u32 uppPgSz;                          // 04 Upper pager page size. Could be different from lower pager's
  Pgno uppPageFile;                     // 04 max pgno in upper pager, used to report filesize
  u8 tblMaxCnt;                         // 01 max entries for table, computed when table is loaded
  u8 tblCurrCnt;                        // 01 curr size / index for next entry to be added
  unsigned char reserved[81];           // 81 pad structure to 100 bytes
};

/*
** Page 1, bytes 200-300, will have a master map for coordinating all the other mapping tables.
** A relatively small table should suffice. If table becomes full, perhaps a larger pagesize will help.
** This table could be extended at the expense of the size of the first page map table.
** After experimenting with various database sizes, this will be revised.
*/
typedef struct CeshimMMTblEntry CeshimMMTblEntry;
struct CeshimMMTblEntry {
  sqlite3_int64 uppOfst;               // 08 upper pager offset
  Pgno lwrPgno;                        // 04 lower pager pgno where actual page map data is stored
};

/*
** Each time we read a page, it'll be associated with a CeshimMemPage
** to store temporary in-memory data that belongs to this page.
*/
typedef struct CeshimMemPage CeshimMemPage;
struct CeshimMemPage {
  DbPage *pDbPage;                     /* Pager page handle */
  Pgno pgno;                           /* The pgno to which this belongs */
  u16 dbHdrOffset;                     /* Offset to the beginning of the header */
  u16 pgHdrOffset;                     /* Offset to the beginning of the data */
  u8 *aData;                           /* Pointer to disk image of the page data */
};

/*
** Mapping table for uncompressed to compressed content.
** The table is stored on page 2 at offset 0.
** The maximum size of table depends on the pager page size.
** If that is not enough, multiple tables will be used.
** As each new table is created, it is stored on the next available page.
*/
typedef struct ceshim_map_entry ceshim_map_entry;
struct __attribute__ ((__packed__)) ceshim_map_entry {
  sqlite3_int64 uppOfst;            // 08 upper pager offset
  Pgno lwrPgno;                     // 04 mapped lower pager pgno
  CeshimCompressedSize cmprSz;      // 02 size of compressed page
  CeshimCompressedOffset cmprOfst;  // 02 lower page offset for compressed page
};

/*
** An instance of this structure is attached to the each trace VFS to
** provide auxiliary information.
*/
typedef struct ceshim_info ceshim_info;
struct ceshim_info {
  sqlite3_vfs *pRootVfs;              /* The underlying real VFS */

  int (*xCompressBound)(void *pCtx, int nSrc);
  int (*xCompress)(void *pCtx, char *aDest, int *pnDest, char *aSrc, int nSrc);
  int (*xUncompress)(void *pCtx, char *aDest, int *pnDest, char *aSrc, int nSrc);

  // Trace Output
  int (*xOut)(const char*, void*);    /* Send output here */
  void *pOutArg;                      /* First argument to xOut */

  const char *zVfsName;               /* Name of this VFS */
  char *zUppJournalPath;              /* Path to redirect upper journal */
  sqlite3_vfs *pCeshimVfs;            /* Pointer back to the ceshim VFS */
  unsigned char zDbHeader[100];       /* Sqlite3 DB header */
  ceshim_header ceshimHeader;         /* Ceshim header with page mapping data */
  CeshimMemPage *pPage1;              /* Page 1 of the pager */
  Pgno lwrPageFile;                   // max pgno in lower pager, used to update pager header
  CeshimMMTblEntry *mmTbl;            // The master mapping table
  u8 mmTblCurrIx;                     // Index of the current page map in mmTbl
  ceshim_map_entry *pPgMap;           // The current page map
  u16 pgMapMaxCnt;                    // Max entries for a page map, based on page size
  u16 pgMapSz;                        // Size in bytes for the page map allocation
  
  // bools
  u8 bPgMapDirty:1;                   // Curr page map needs to be persisted
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
  u32 pageSize;                     /* Page size of the lower pager */
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
** Forward declarations
*/
static CeshimMemPage *memPageFromDbPage(DbPage *pDbPage, Pgno mappedPgno);
static int ceshimNewDatabase(ceshim_file *pFile);
static int ceshimWriteUncompressed(ceshim_file *, Pgno, CeshimCompressedOffset, const void *zBuf, int iAmt);
static int ceshimReadUncompressed(ceshim_file *, Pgno, CeshimCompressedOffset, void *zBuf, int iAmt);
static int ceshimSaveHeader(ceshim_file *p);
static int ceshimLoadHeader(ceshim_file *p);
//static int ceshimCreateNewPageMap(ceshim_file *p);

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
** Map the upper pager's journal file onto a different name.
** findCreateFileMode() in os_unix.c requires journal file to be in same directory
** or not have '-' in name. We'll just append "btree" to distinguish it from ours.
** Note: everything after the '-' must be alphanumeric only - No punctuation allowed -
** or an assertion will be triggered in debug mode.
*/
const char *ceshimMapPath(ceshim_info *pInfo, const char *zName){
  static const char *zTail = "btree";
  if( strstr(zName, "-journal")==0 ) return zName;
  char *zUppJournalPath = pInfo->zUppJournalPath;
  if( zUppJournalPath == NULL ){
    zUppJournalPath = sqlite3_malloc((int)(strlen(zName)+strlen(zTail))+1);
    *zUppJournalPath = '\0';
    strcat(zUppJournalPath, zName);
    strcat(zUppJournalPath, zTail);
    pInfo->zUppJournalPath = zUppJournalPath;
  }
  return zUppJournalPath;
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
  ceshim_file *p,
  Pgno pgno,
  CeshimCompressedOffset offset,
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

static void ceshimReleasePage1(ceshim_file *p){
  ceshim_info *pInfo = p->pInfo;
  if( pInfo->pPage1 ){

//    unsigned char buf[4];
//    put4byte(buf, pInfo->ceshimHeader.uppPageFile);
//    int rc = ceshimWrite((sqlite3_file *)p, &buf, 4, 28);

    sqlite3PagerUnref(pInfo->pPage1->pDbPage);
    pInfo->pPage1 = NULL;
  }
}

// create master map table at 200-299
static int ceshimCreateMMTbl(ceshim_file *p, int *memSzOut){
  ceshim_info *pInfo = p->pInfo;
  u16 maxSz = p->pageSize - CESHIM_DB_HEADER_SIZE;
  u8 maxEntries = maxSz / sizeof(CeshimMMTblEntry);
  pInfo->ceshimHeader.tblMaxCnt = maxEntries;
  pInfo->ceshimHeader.tblCurrCnt = 0;
  int memSz = maxEntries*sizeof(CeshimMMTblEntry);
  if( !(pInfo->mmTbl = sqlite3_malloc(memSz)) ) return SQLITE_NOMEM;
  if( memSzOut ) *memSzOut = memSz;
  return SQLITE_OK;
}

static int ceshimSavePagemapData(ceshim_file *p){
  int rc = SQLITE_OK;
  ceshim_info *pInfo = p->pInfo;
  if( pInfo->bPgMapDirty ){
    Pgno pgno = pInfo->mmTbl[pInfo->mmTblCurrIx].lwrPgno;
    rc = ceshimWriteUncompressed(p, pgno, 0, pInfo->pPgMap, pInfo->pgMapSz);
    if( rc==SQLITE_OK ) pInfo->bPgMapDirty = 0;
  }
  return rc;
}

static int ceshimSaveMMTbl(ceshim_file *p){
  int rc;
  ceshim_info *pInfo = p->pInfo;
  ceshim_header *header = &pInfo->ceshimHeader;
  int memSz = header->tblMaxCnt*sizeof(CeshimMMTblEntry);
  rc = ceshimWriteUncompressed(p, 1, CESHIM_DB_MMTBL_OFST, pInfo->mmTbl, memSz);
  if( rc==SQLITE_OK ) rc = ceshimSavePagemapData(p);
  return rc;
}

static int ceshimLoadPagemapData(ceshim_file *p, u8 ix){
  int rc;
  ceshim_info *pInfo = p->pInfo;
  assert( pInfo->bPgMapDirty==0 );
  Pgno pgno = pInfo->mmTbl[ix].lwrPgno;
  rc = ceshimReadUncompressed(p, pgno, 0, pInfo->pPgMap, pInfo->pgMapSz);
  if( rc==SQLITE_OK ) pInfo->mmTblCurrIx = ix;
  return rc;
}

static int ceshimLoadMMTbl(ceshim_file *p){
  int rc;
  ceshim_info *pInfo = p->pInfo;
//  ceshim_header *header = &pInfo->ceshimHeader;
  // TODO: ensure header has already been loaded

//  assert( header->tblMaxCnt>0 );
  assert( pInfo->mmTbl==NULL );
  int memSz;
  if( (rc = ceshimCreateMMTbl(p, &memSz)) == SQLITE_OK ){
    // TODO: load with get4Bytes
    rc = ceshimReadUncompressed(p, 1, CESHIM_DB_MMTBL_OFST, pInfo->mmTbl, memSz);
  }else rc = SQLITE_NOMEM;
  return rc;
}

static int ceshimPagerLock(ceshim_file *p){
  ceshim_info *pInfo = p->pInfo;
  int rc;
  assert( pInfo->pPage1==0 );
  if( (rc = sqlite3PagerSharedLock(p->pPager)) == SQLITE_OK ){
    DbPage *pDbPage1;
    if( (rc = sqlite3PagerGet(p->pPager, 1, &pDbPage1, 0)) == SQLITE_OK ){
      pInfo->pPage1 = memPageFromDbPage(pDbPage1, 1);
      int nPageFile = 0;
      sqlite3PagerPagecount(p->pPager, &nPageFile);

      // calc max entries for each page map based on page size
      pInfo->pgMapMaxCnt = p->pageSize / sizeof(ceshim_map_entry);
      pInfo->pgMapSz = pInfo->pgMapMaxCnt * sizeof(ceshim_map_entry);

      /* Allocate space for a single page map.
         Only one page map will be in memory at a time. */
      pInfo->pPgMap = sqlite3_malloc(pInfo->pgMapSz);
      if( !pInfo->pPgMap ) rc = SQLITE_NOMEM;

      if( nPageFile==0 ){
        /* We will be creating a new database so set up some data that is
           needed right away that would be too late to do in ceshimNewDatabase(). */
        if( (rc = ceshimCreateMMTbl(p, NULL))==SQLITE_OK ){
          pInfo->mmTbl[0].lwrPgno = 2;
          pInfo->ceshimHeader.tblCurrCnt = 1;
        }
      }else{
        // restore some data
        //memcpy(&pInfo->ceshimHeader, pInfo->pPage1->aData+CESHIM_DB_HEADER2_OFST, CESHIM_DB_HEADER2_SZ);
        rc = ceshimLoadMMTbl(p);
        if( rc==SQLITE_OK ) rc = ceshimLoadPagemapData(p, 0);
        if( rc==SQLITE_OK ) rc = ceshimLoadHeader(p); // must be done after ceshimLoadMMTbl()
      }
      /* reminder: do not call sqlite3PagerUnref(pDbPage1) here as this will
         cause pager state to reset to PAGER_OPEN which is not desirable for writing to pager. */
    }
  }
  return rc;
}

static int ceshimPagerWrite(ceshim_file *p, PgHdr *pPg){
  int rc = SQLITE_OK;
  if( p->nTransactions == 0 ){
    if( (rc = sqlite3PagerBegin(p->pPager, 0, 1))==SQLITE_OK ){
      p->nTransactions++;
      if( p->pInfo->lwrPageFile==0 ){
        rc = ceshimNewDatabase(p);
      }
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
  DbPage *pPage = NULL;
  if( (rc = sqlite3PagerGet(pFile->pPager, pgno, &pPage, 0)) == SQLITE_OK ){
    void *data = sqlite3PagerGetData(pPage);
    if( (rc = ceshimPagerWrite(pFile, pPage)) == SQLITE_OK ){
      memcpy(data+offset, zBuf, iAmt);
    }
    sqlite3PagerUnref(pPage);
  }
  return rc;
}

static int ceshimSaveHeader(ceshim_file *p){
  ceshim_header *header = &p->pInfo->ceshimHeader;
  u8 buf[CESHIM_DB_HEADER2_SZ];
  memcpy(buf, &header->schema, 1);
  put4byte(buf+1, header->currPgno);
  put2byte(buf+5, header->currPageOfst);
  put2byte(buf+7, header->pgMapCnt);
  put4byte(buf+9, header->uppPgSz);
  put4byte(buf+13, header->uppPageFile);
  memcpy(buf+17, &header->tblMaxCnt, 1);
  memcpy(buf+18, &header->tblCurrCnt, 1);
  memset(buf+19, 0, 81);
  return ceshimWriteUncompressed(p, 1, CESHIM_DB_HEADER1_SZ, buf, CESHIM_DB_HEADER2_SZ);
}

static int ceshimLoadHeader(ceshim_file *p){
  ceshim_header *header = &p->pInfo->ceshimHeader;
  u8 buf[CESHIM_DB_HEADER2_SZ];
  int rc;
  if( (rc = ceshimReadUncompressed(p, 1, CESHIM_DB_HEADER2_OFST, buf, CESHIM_DB_HEADER2_SZ))==SQLITE_OK ){
    header->schema = buf[0];
    header->currPgno = get4byte(buf+1);
    header->currPageOfst = get2byte(buf+5);
    header->pgMapCnt = get2byte(buf+7);
    header->uppPgSz = get4byte(buf+9);
    header->uppPageFile = get4byte(buf+13);
    header->tblMaxCnt = buf[17];
    header->tblCurrCnt = buf[18];
  }
  return rc;
}

static CeshimMemPage *memPageFromDbPage(DbPage *pDbPage, Pgno mappedPgno){
  CeshimMemPage* pPg = (CeshimMemPage *)sqlite3PagerGetExtra(pDbPage);
  if(mappedPgno != pPg->pgno  ){
    pPg->pgno = mappedPgno;
    pPg->pDbPage = pDbPage;
    pPg->dbHdrOffset = mappedPgno==1 ? CESHIM_DB_HEADER_SIZE : 0;
    pPg->pgHdrOffset = 0; // Not used anymore
    pPg->pDbPage->pgno = mappedPgno; // pager uses this to determine pager size
    pPg->aData = sqlite3PagerGetData(pDbPage);
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

/*
static int ceshimCreateNewPageMap(ceshim_file *p){
  ceshim_info *pInfo = p->pInfo;
  ceshim_header *header = &pInfo->ceshimHeader;
  assert( pInfo->pgMap==NULL || (pInfo->pgMapMaxCnt && header->pgMapCnt==pInfo->pgMapMaxCnt) );
  int rc = SQLITE_OK;
  // first save current pagemap
  if( p->pInfo->pgMap ) rc = ceshimSavePagemapData(p, pInfo->nCurrPgMap);
  if( rc==SQLITE_OK ){
    pInfo->pgMap = sqlite3_malloc(pInfo->pgMapSz);
    if( !pInfo->pgMap ) rc = SQLITE_NOMEM;
  }
  return rc;
}*/

static int ceshimSwitchPageMap(ceshim_file *p, sqlite_int64 iUppOfst){
  int rc = SQLITE_ERROR;
  ceshim_info *pInfo = p->pInfo;
  ceshim_header *header = &pInfo->ceshimHeader;
  u8 ix = 0;

  // find page map
  // check last entry first (edge case)
  if( iUppOfst >= pInfo->mmTbl[header->tblCurrCnt-1].uppOfst ){
    ix = header->tblCurrCnt-1;
    rc = SQLITE_OK;
  }else{
    for(int i=0; i<header->tblCurrCnt-1; i++){
      if(
        pInfo->mmTbl[i].uppOfst <= iUppOfst
        && iUppOfst < pInfo->mmTbl[i+1].uppOfst
      ){
        ix = i;
        rc = SQLITE_OK;
        break;
      }
    }
  }

  if( rc==SQLITE_OK && ix != pInfo->mmTblCurrIx ){
    ceshim_printf(pInfo, "\nSwitching to map #%u for offset %lld\n", (unsigned)ix, iUppOfst);
    // save
    if( (rc = ceshimSavePagemapData(p))==SQLITE_OK ){
      // reset
      memset(pInfo->pPgMap, 0, pInfo->pgMapSz);
      //load
      rc = ceshimLoadPagemapData(p, ix);
      if( rc==SQLITE_OK ) pInfo->mmTblCurrIx = ix;
    }
  }
  return rc;
}

static int ceshimPageMapGet(
  ceshim_file *pFile,
  sqlite_uint64 uSrcOfst,
  Pgno *outUppPgno,
  Pgno *outLwrPgno,
  CeshimCompressedOffset *outCmpOfst,
  CeshimCompressedSize *outCmpSz,
  u8 *outIx
){
  ceshim_info *pInfo = pFile->pInfo;
  ceshim_header *header = &pInfo->ceshimHeader;
  if( outUppPgno ) *outUppPgno = (Pgno)(uSrcOfst/header->uppPgSz+1);
  ceshimSwitchPageMap(pFile, uSrcOfst);
  if( pInfo->pPgMap ){
    u8 maxCnt = pInfo->mmTblCurrIx==header->tblCurrCnt-1 ? header->pgMapCnt : pInfo->pgMapMaxCnt;
    for(int i=0; i<maxCnt; i++){
      if(
         pInfo->pPgMap[i].uppOfst <= uSrcOfst
         && uSrcOfst < pInfo->pPgMap[i].uppOfst+header->uppPgSz
      ){
        if( outLwrPgno ) *outLwrPgno = pInfo->pPgMap[i].lwrPgno;
        if( outCmpSz ) *outCmpSz = pInfo->pPgMap[i].cmprSz;
        if( outCmpOfst ) *outCmpOfst = pInfo->pPgMap[i].cmprOfst;
        if( outIx ) *outIx = i;
        return SQLITE_OK;
      }
    }
  }
  return SQLITE_ERROR;
}

int ceshimAddPageEntry(
  ceshim_file *pFile,
  sqlite3_int64 uppOfst,
  CeshimCompressedSize cmpSz,
  CeshimCompressedOffset *outCmpOfst,
  Pgno *outLwrPgno
){
  ceshim_info *pInfo = pFile->pInfo;
  ceshim_header *header = &pInfo->ceshimHeader;
  CeshimCompressedOffset ofst = 0;
  u32 realPageSize = pFile->pageSize - (header->currPgno == 1 ? CESHIM_DB_HEADER_SIZE : 0);
  ofst = header->currPageOfst;
  header->currPageOfst += cmpSz;
  if( header->currPageOfst > realPageSize ){
    // current page can't hold anymore, start new page.
    header->currPageOfst = cmpSz;
    do{ header->currPgno++; } while( header->currPgno <= pInfo->mmTbl[header->tblCurrCnt-1].lwrPgno );
    ofst = 0;
  }
  if( outLwrPgno ) *outLwrPgno = header->currPgno;
  // if no more room, start a new map
  if( header->pgMapCnt == pInfo->pgMapMaxCnt ){
    if( pInfo->mmTblCurrIx == header->tblMaxCnt ){
      // We've run out of room in the master map table.
      // User will need to increase pager size.
      // TODO: Create appropriate error code
      assert( 0 );
      return SQLITE_ERROR;
    }
    // can't change pInfo->mmTblCurrIx until after ceshimSwitchPageMap
    CeshimMMTblEntry *entry = &pInfo->mmTbl[header->tblCurrCnt];
    entry->uppOfst = uppOfst;
    entry->lwrPgno = header->currPgno+1;
    header->tblCurrCnt++;
    header->pgMapCnt = 0;
    ceshimSwitchPageMap(pFile, uppOfst);
  }
  // append entry
  u16 ix = header->pgMapCnt++;
  ceshim_map_entry *entry = &pInfo->pPgMap[ix];
  entry->uppOfst = uppOfst;
  entry->lwrPgno = outLwrPgno ? *outLwrPgno : 0;
  entry->cmprSz = cmpSz;
  entry->cmprOfst = outCmpOfst ? ofst : 0;
  pInfo->bPgMapDirty = 1;
  if( outCmpOfst ) *outCmpOfst = ofst;
  return SQLITE_OK;
}

/*
** Add pager map entry before writing to lower pager
** to get pgno & offset for pager write operation.
**
** uppOfst - upper pager offset
** cmpSz - compressed size to save
** lwrPgno OUT - mapped pgno
** outCmpOfst - offset to write compressed data to
**/
static int ceshimPageMapSet(
  ceshim_file *pFile,
  sqlite_int64 uppOfst,
  CeshimCompressedSize cmpSz,
  Pgno *outUppPgno,
  Pgno *outLwrPgno,
  CeshimCompressedOffset *outCmpOfst
){
  ceshim_info *pInfo = pFile->pInfo;
  ceshim_header *header = &pInfo->ceshimHeader;
  CeshimCompressedSize oldCmpSz;
  int rc = SQLITE_OK;
  u8 ix;

  assert( outUppPgno );
  assert( outLwrPgno );
  assert( outCmpOfst );
  ceshimSwitchPageMap(pFile, uppOfst);
  if( (rc = ceshimPageMapGet(pFile, uppOfst, outUppPgno, outLwrPgno, outCmpOfst, &oldCmpSz, &ix))==SQLITE_OK ){
    // Update map entry data and get new compressed page slot at end of db.
    // Any previously used slot will be abandoned and can be recovered via vacuum.
    if( oldCmpSz==0 || cmpSz>oldCmpSz ){
      // Fill the placeholder entry with real data
      ceshim_map_entry *mapEntry = &pInfo->pPgMap[ix];

      // need to add new compressed page and point to it.
      // TODO: clean up repeated code below
      CeshimCompressedOffset ofst = 0;
      u32 realPageSize = pFile->pageSize - (header->currPgno == 1 ? CESHIM_DB_HEADER_SIZE : 0);
      ofst = header->currPageOfst;
      header->currPageOfst += cmpSz;
      if( header->currPageOfst > realPageSize ){
        // current page can't hold anymore, start new page.
        header->currPageOfst = cmpSz;
        do{ header->currPgno++; } while( header->currPgno <= pInfo->mmTbl[header->tblCurrCnt-1].lwrPgno );
        ofst = 0;
      }
      mapEntry->lwrPgno = *outLwrPgno = header->currPgno;
      mapEntry->cmprOfst = *outCmpOfst = ofst;
      mapEntry->cmprSz = cmpSz;
      pInfo->bPgMapDirty = 1;
      ceshim_printf(pInfo, "Updated placeholder entry (uppOfst=%lld, lwrPgno=%lu,cmpOfst=%lu,cmpSz=%lu) \n",
        (long long)mapEntry->uppOfst, (unsigned long)mapEntry->lwrPgno, (unsigned long)mapEntry->cmprOfst, (unsigned long)mapEntry->cmprSz);
      return SQLITE_OK;
    }else if( cmpSz<oldCmpSz ){
      // Update map entry data and keep compressed page slot. Abandoned space will be recovered via vacuum.
      pInfo->pPgMap[ix].cmprSz = cmpSz;
      pInfo->bPgMapDirty = 1;
    }
    // Entry already exists, so check to see if compressed size has changed. If so,
    // we need to shift compressed pages below this one, if there's room to do so.
    else if( cmpSz>oldCmpSz ){
      u16 delta = cmpSz - oldCmpSz;
      // do we have room to shift?
      ix = (pInfo->mmTblCurrIx==header->tblCurrCnt-1 ? header->pgMapCnt : pInfo->pgMapMaxCnt) - 1;
      CeshimCompressedSize reqSz = pInfo->pPgMap[ix].cmprOfst + pInfo->pPgMap[ix].cmprSz + delta;
      if( reqSz <= pInfo->pgMapSz ){
        // shift
        void *buf = sqlite3_malloc(pFile->pageSize);
        while( pInfo->pPgMap[ix].uppOfst != uppOfst ){
          if( *outLwrPgno != pInfo->pPgMap[ix].lwrPgno ){
            ix--;
            continue;
          }
          ceshim_map_entry *mapEntry = &pInfo->pPgMap[ix];
          ceshim_printf(pInfo, "Map Entry Move (uppOfst=%lld,lwrPgno=%lu,cmpOfst=%lu,cmpSz=%lu) to (uppOfst=%lld,lwrPgno=%lu,cmpOfst=%lu,cmpSz=%lu)\n",
            (long long)mapEntry->uppOfst, (unsigned long)mapEntry->lwrPgno, (unsigned long)mapEntry->cmprOfst, (unsigned long)mapEntry->cmprSz,
            (long long)mapEntry->uppOfst, (unsigned long)mapEntry->lwrPgno, (unsigned long)(mapEntry->cmprOfst + delta), (unsigned long)mapEntry->cmprSz);
          if( (rc = ceshimReadUncompressed(pFile, mapEntry->lwrPgno, mapEntry->cmprOfst, buf, mapEntry->cmprSz))==SQLITE_OK ){
            if( (rc = ceshimWriteUncompressed(pFile, mapEntry->lwrPgno, mapEntry->cmprOfst + delta, buf, mapEntry->cmprSz))==SQLITE_OK ){
              mapEntry->cmprOfst += delta;
              ix--;
            }
          }
        }
        sqlite3_free(buf);
        ceshim_printf(pInfo, "Map Entry Adjust (uppOfst=%lld, lwrPgno=%lu,cmpOfst=%lu,cmpSz=%lu) to (uppOfst=%lld, lwrPgno=%lu,cmpOfst=%lu,cmpSz=%lu)\n",
          (long long)pInfo->pPgMap[ix].uppOfst, (unsigned long)pInfo->pPgMap[ix].lwrPgno, (unsigned long)pInfo->pPgMap[ix].cmprOfst, (unsigned long)pInfo->pPgMap[ix].cmprSz,
          (long long)pInfo->pPgMap[ix].uppOfst, (unsigned long)(*outLwrPgno), (unsigned long)pInfo->pPgMap[ix].cmprOfst, (unsigned long)cmpSz);
        pInfo->pPgMap[ix].cmprSz = cmpSz;
        pInfo->pPgMap[ix].lwrPgno = *outLwrPgno;
        header->currPageOfst += delta;
      }else{
        // not enough room to shift
        // can we solve by requiring a larger page size?
        assert( 0 );
      }
    }
    return rc;
  }else{
    sqlite3_int64 nextOfst = header->pgMapCnt==0 ? 0 : pInfo->pPgMap[header->pgMapCnt-1].uppOfst + header->uppPgSz;
    while( uppOfst>nextOfst ){
      ceshimAddPageEntry(pFile, nextOfst, 0, NULL, NULL);
      ceshim_printf(pInfo, "Added intermin entry (uppOfst=%lld, lwrPgno=0,cmpOfst=0,cmpSz=0)\n", (long long)nextOfst);
      nextOfst += header->uppPgSz;
    }
    assert( uppOfst==nextOfst );
    ceshimAddPageEntry(pFile, uppOfst, cmpSz, outCmpOfst, outLwrPgno);
  }
  return SQLITE_OK;
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

    int nPageFile = 0;   /* Number of pages in the database file */
    sqlite3PagerPagecount(p->pPager, &nPageFile);
    assert( pInfo->lwrPageFile==nPageFile );

    u8 buf[4];
    sqlite3Put4byte(buf, pInfo->lwrPageFile);
    rc = ceshimWriteUncompressed(p, 1, 28, buf, 4);
    rc = ceshimSaveHeader(p);

    if( (rc = ceshimSaveMMTbl(p))==SQLITE_OK ){
      for(int i=0; i<p->nTransactions; i++){
        if( (rc = sqlite3PagerCommitPhaseOne(p->pPager, NULL, 0))==SQLITE_OK ){
          sqlite3PagerCommitPhaseTwo(p->pPager);
        }
      }
      p->nTransactions = 0;

      if( rc==SQLITE_OK ){
        ceshimReleasePage1(p);
        if( (rc = sqlite3PagerClose(p->pPager))==SQLITE_OK ){
          p->pPager = NULL;
          if( pInfo->zUppJournalPath ){
            sqlite3_free(pInfo->zUppJournalPath);
            pInfo->zUppJournalPath = NULL;
          }
          if( pInfo->mmTbl ){
            sqlite3_free(pInfo->mmTbl);
            pInfo->mmTbl = NULL;
          }
          if( pInfo->pPgMap ){
            sqlite3_free(pInfo->pPgMap);
            pInfo->pPgMap = NULL;
          }
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
  u32 uppPgSz = pInfo->ceshimHeader.uppPgSz;
  int rc;
  ceshim_printf(pInfo, "%s.xRead(%s,ofst=%lld,amt=%d)", pInfo->zVfsName, p->zFName, iOfst, iAmt);

  if( p->pPager && pInfo->pPage1 ){
    DbPage *pPage;
    Pgno uppPgno, mappedPgno;
    CeshimCompressedOffset cmprPgOfst;
    CeshimCompressedSize uCmpPgSz;
    if( (rc = ceshimPageMapGet(p, iOfst, &uppPgno, &mappedPgno, &cmprPgOfst, &uCmpPgSz, NULL)) == SQLITE_ERROR ){
      if( iOfst<uppPgSz ) {
        mappedPgno = CESHIM_FIRST_MAPPED_PAGE;
        rc = SQLITE_OK;
      }
    }
    if( mappedPgno==0 ){
      memset(zBuf, 0, iAmt);
      return SQLITE_OK;
    }
    if( rc==SQLITE_OK &&  (rc = sqlite3PagerGet(p->pPager, mappedPgno, &pPage, 0)) == SQLITE_OK ){
      CeshimMemPage *pMemPage = memPageFromDbPage(pPage, mappedPgno);
      ceshim_printf(pInfo, "\n%s.xRead(%s,pgno=%u->%u,ofst=%lld,amt=%d,cmprPgOfst=%u,cmprSz=%u)",
        pInfo->zVfsName, p->zFName, uppPgno, mappedPgno, iOfst, iAmt, cmprPgOfst, uCmpPgSz);
      if( uCmpPgSz > 0 ){ // <- should be able to remove this check now
        int iDstAmt = uppPgSz;
        void *pBuf = sqlite3_malloc(iDstAmt);
        pInfo->xUncompress(
          NULL,
          pBuf,
          &iDstAmt,
          (char *)pMemPage->aData
            +pMemPage->dbHdrOffset
            +pMemPage->pgHdrOffset
            +cmprPgOfst,
          uCmpPgSz
        );
        u16 uBufOfst = iOfst % uppPgSz;
        memcpy(zBuf, pBuf+uBufOfst, iAmt);
        sqlite3_free(pBuf);
      }else{
        memset(zBuf, 0, iAmt);
      }
      sqlite3PagerUnref(pPage);
    }
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
      if( pBuf ){
        CeshimCompressedOffset cmprPgOfst;
        pInfo->xCompress(NULL, pBuf, &pnDest, (void *)zBuf, iAmt);
        ceshimPageMapSet(p, iOfst, pnDest, &uppPgno, &mappedPgno, &cmprPgOfst);
        ceshim_printf(pInfo, "%s.xWrite(%s, pgno=%u->%u, offset=%06lld, amt=%06d)", pInfo->zVfsName, p->zFName, uppPgno, mappedPgno, iOfst, iAmt);
        if( rc==SQLITE_OK && (rc = sqlite3PagerGet(p->pPager, mappedPgno, &pPage, 0))==SQLITE_OK ){
          // write
          CeshimMemPage *pMemPage = memPageFromDbPage(pPage, mappedPgno);
            if( (rc = ceshimPagerWrite(p, pPage))==SQLITE_OK ){
              ceshim_printf(
                pInfo,
                "\n%s.xWrite(%s, pgno=%u->%u, offset=%06lld, amt=%06d, compressed=%06d)",
                pInfo->zVfsName,
                p->zFName, uppPgno, mappedPgno,
                pMemPage->dbHdrOffset+pMemPage->pgHdrOffset+cmprPgOfst,
                iAmt, pnDest
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
              if( pInfo->ceshimHeader.uppPageFile<uppPgno ) pInfo->ceshimHeader.uppPageFile = uppPgno;
              if( pInfo->lwrPageFile<mappedPgno ) pInfo->lwrPageFile = mappedPgno;
            }
          sqlite3PagerUnref(pPage);
        }
        sqlite3_free(pBuf);
      }
    }
  }else{
    ceshim_printf(pInfo, "%s.xWrite(%s, offset=%06lld, amt=%06d)", pInfo->zVfsName, p->zFName, iOfst, iAmt);
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
  ceshim_header *header = &pInfo->ceshimHeader;
  int rc;
  ceshim_printf(pInfo, "%s.xFileSize(%s)", pInfo->zVfsName, p->zFName);
  if(p->pPager ){
    *pSize = header->uppPageFile * header->uppPgSz;
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

static int ceshimPragma(sqlite3_file *pFile, const char *op, const char *arg){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  if( strcmp(op, "page_size")==0 ){
    pInfo->ceshimHeader.uppPgSz = (u32)sqlite3Atoi(arg);
  }
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
      ceshimPragma(pFile, a[1], a[2]);
      break;
    }
    case SQLITE_FCNTL_MMAP_SIZE: {
      sqlite3_snprintf(sizeof(zBuf), zBuf, "SQLITE_FCNTL_MMAP_SIZE,%d", *(int*)pArg);
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
    const char *_zName,
    sqlite3_file *pFile,
    int flags,
    int *pOutFlags
){
  u8 nReserve;
  int rc;

  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  const char *zName = ceshimMapPath(pInfo, _zName);
  u32 nParamBlockSz = 0;

  p->pInfo = pInfo;
  p->zFName = zName ? fileTail(zName) : "<temp>";
  p->pReal = (sqlite3_file *)&p[1];
  p->pPager = NULL;

  // Process URI parameters
  if( flags & SQLITE_OPEN_URI){
    const char *zParamBlockSize = sqlite3_uri_parameter(_zName, "block_size");
    if( zParamBlockSize ) nParamBlockSz = (u32)sqlite3Atoi(zParamBlockSize);
  }

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
      if( (rc = sqlite3PagerOpen(pInfo->pRootVfs, &p->pPager, zName, EXTRA_SIZE, 0, flags, pageReinit))==SQLITE_OK){
        if( rc==SQLITE_OK ){
          sqlite3PagerSetJournalMode(p->pPager, PAGER_JOURNALMODE_DELETE);
//          sqlite3PagerJournalSizeLimit(p->pPager, -1);
//          rc = sqlite3PagerLockingMode(p->pPager, PAGER_LOCKINGMODE_NORMAL);
//          sqlite3PagerSetMmapLimit(pBt->pPager, db->szMmap); /* advisory, except if 0 */
          if( (rc = sqlite3PagerReadFileheader(p->pPager,sizeof(pInfo->zDbHeader),pInfo->zDbHeader)) == SQLITE_OK ){
            p->pageSize = (pInfo->zDbHeader[16]<<8) | (pInfo->zDbHeader[17]<<16);
            if( p->pageSize<512 || p->pageSize>SQLITE_MAX_PAGE_SIZE
               || ((p->pageSize-1)&p->pageSize)!=0 ){
              p->pageSize = nParamBlockSz; // if 0, sqlite3PagerSetPagesize will set page size
              nReserve = 0;
            }else{
              nReserve = pInfo->zDbHeader[20];
              pInfo->lwrPageFile = sqlite3Get4byte(pInfo->zDbHeader+28);
            }
            sqlite3PagerSetMmapLimit(p->pPager, 0);
            if( (rc = sqlite3PagerSetPagesize(p->pPager, &p->pageSize, nReserve)) == SQLITE_OK ){
              p->usableSize = p->pageSize - nReserve;
              sqlite3PagerSetCachesize(p->pPager, SQLITE_DEFAULT_CACHE_SIZE);
              rc = ceshimPagerLock(p);
            }
          }
        }else{
          ceshimClose(pFile);
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
static int ceshimDelete(sqlite3_vfs *pVfs, const char *_zPath, int dirSync){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  int rc;
  const char *zPath = ceshimMapPath(pInfo, _zPath);
  ceshim_printf(pInfo, "%s.xDelete(\"%s\",%d) BYPASS", pInfo->zVfsName, zPath, dirSync);
  rc = pRoot->xDelete(pRoot, zPath, dirSync);
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Test for access permissions.
** Return true via *pResOut if the requested permission
** is available, or false otherwise.
*/
static int ceshimAccess(
  sqlite3_vfs *pVfs,
  const char *_zPath,
  int flags,
  int *pResOut
){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  const char *zPath = ceshimMapPath(pInfo, _zPath);
  int rc = SQLITE_OK;
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
  const char *_zName,
  sqlite3_syscall_ptr pFunc
){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  const char *zName = ceshimMapPath(pInfo, _zName);
  return pRoot->xSetSystemCall(pRoot, zName, pFunc);
}
static sqlite3_syscall_ptr ceshimGetSystemCall(
  sqlite3_vfs *pVfs,
  const char *_zName
){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  const char *zName = ceshimMapPath(pInfo, _zName);
  return pRoot->xGetSystemCall(pRoot, zName);
}
static const char *ceshimNextSystemCall(sqlite3_vfs *pVfs, const char *_zName){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  const char *zName = ceshimMapPath(pInfo, _zName);
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
  void *pOutArg                     /* 2nd argument to xOut.  ex: stderr */
){
  sqlite3_vfs *pNew;
  sqlite3_vfs *pRoot;
  ceshim_info *pInfo;
  int nName;
  int nByte;

  // Allow parameters to be passed with database filename in URI form.
  sqlite3_config(SQLITE_CONFIG_URI, 1);

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

  // Move to ceshimNewDatabase()?
  pInfo->ceshimHeader.schema = CESHIM_FILE_SCHEMA_NO;
  pInfo->ceshimHeader.currPgno = CESHIM_FIRST_MAPPED_PAGE;
  pInfo->ceshimHeader.uppPgSz = SQLITE_DEFAULT_PAGE_SIZE;

  ceshim_printf(pInfo, "%s.enabled_for(\"%s\")\n", pInfo->zVfsName, pRoot->zName);
  return sqlite3_vfs_register(pNew, 0);
}

int ceshim_unregister(const char *zName){
  sqlite3_vfs *pVfs = sqlite3_vfs_find(zName);
  if( pVfs ){
    //ceshim_info *pInfo = (ceshim_info *)pVfs->pAppData;
    sqlite3_free(pVfs);
    return SQLITE_OK;
  }
  return SQLITE_NOTFOUND;
}
