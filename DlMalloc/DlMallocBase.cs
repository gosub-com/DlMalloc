// The MIT License (MIT)
// 
// Copyright (c) 2019 by Jeremy Spiller
// 
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//  This is a version (aka dlmalloc) of malloc/free/realloc written by
//  Doug Lea and released to the public domain, as explained at
//  http://creativecommons.org/publicdomain/zero/1.0/ Send questions,
//  comments, complaints, performance data, etc to dl@cs.oswego.edu
//
//* Version 2.8.6 Wed Aug 29 06:57:58 2012  Doug Lea
//   Note: There may be an updated version of this malloc obtainable at
//           ftp://gee.cs.oswego.edu/pub/misc/malloc.c

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Gosub.DlMalloc
{
    // size_t must be at least as big as a pointer, but may also be larger.
    // Therefore, setting size_t to Uint64 accommodates both 32 and 64 bit
    // pointer sizes.  This could be changed to UInt32 when running only
    // on 32 bit systems, but it wouldn't affect the size of internal data
    // structures since they are determined via sizeof(IntPtr), etc.
    using size_t = System.UInt64;

    public class DlMallocException : Exception
    {
        public DlMallocException(string message) : base(message) { }
    }

    /// <summary>
    /// This is the base class that implements the DlMalloc algorithms.
    /// To use this class, at least CallMoreCore and CallReleaseCore need to
    /// be implemented.  Other Call* functions can optionally be overriden as well.
    /// Call or expose protected members Malloc and Free to implement malloc and free.
    /// </summary>
    public abstract unsafe class DlMallocBase : IDisposable
    {
        /// <summary>
        /// This was originally CALL_MMAP and is used to get more memory from
        /// the system. It's similar to CALL_MMAP, but the function can increase
        /// the size of allocated memory if desired  (must be in units of page size).
        /// Returns null when out of memory or on error.
        /// </summary>
        protected abstract void* CallMoreCore(ref ulong length);

        /// <summary>
        /// This was originally CALL_MUNMAP and is used to release memory pages
        /// back to the OS.  This function works with pages, not with units
        /// individually allocated by CallMoreCore.  Therefore it could try to
        /// free part of an allocated memory block or even multiple blocks at a time.
        /// Return true for success, or false for failure (in which
        /// case the pages are retained and used for future requests)
        /// </summary>
        protected abstract bool CallReleaseCore(void* address, ulong length);

        /// <summary>
        /// This is called after DlMalloc has been disposed.  Since CallReleaseCore
        /// works with pages instead of allocation units, it may be more convenient
        /// to cleanup any left over memory allocations here.
        /// </summary>
        protected virtual void CallDisposeFinal()
        {

        }

        /// <summary>
        /// Called when the heap is known to be corrupted.  Throws an exception
        /// and calls ResetOnError by default.
        /// </summary>
        protected virtual void CallCorruptionErrorAction()
        {
            ResetOnError();
            throw new DlMallocException("Malloc Corrupted: TBD: Give more info about address");
        }

        /// <summary>
        /// Called when the malloc is used incorrectly.  Throws an exception
        /// and calls ResetOnError by default.
        /// </summary>
        protected virtual void CallUsageErrorAction(void* m2)
        {
            ResetOnError();
            throw new DlMallocException("Malloc Usage Error: TBD: Give more info about address");
        }

        /// <summary>
        /// Called before malloc returns NULL.  The default action is to throw an exception
        /// </summary>
        protected virtual void CallMallocFailureAction()
        {
            throw new DlMallocException("Malloc out of memory");
        }

        //  Top
        //    The topmost chunk of the currently active segment. Its size is
        //    cached in topsize.  The actual size of topmost space is
        //    topsize+TOP_FOOT_SIZE, which includes space reserved for adding
        //    fenceposts and segment records if necessary when getting more
        //    space from the system.  The size at which to autotrim top is
        //    cached from mparams in trim_check, except that it is disabled if
        //    an autotrim fails.

        //  Designated victim (dv)
        //    This is the preferred chunk for servicing small requests that
        //    don't have exact fits.  It is normally the chunk split off most
        //    recently to service another small request.  Its size is cached in
        //    dvsize. The link fields of this chunk are not maintained since it
        //    is not kept in a bin.

        //  SmallBins
        //    An array of bin headers for free chunks.  These bins hold chunks
        //    with sizes less than MIN_LARGE_SIZE bytes. Each bin contains
        //    chunks of all the same size, spaced 8 bytes apart.  To simplify
        //    use in double-linked lists, each bin header acts as a malloc_chunk
        //    pointing to the real first node, if it exists (else pointing to
        //    itself).  This avoids special-casing for headers.  But to avoid
        //    waste, we allocate only the fd/bk pointers of bins, and then use
        //    repositioning tricks to treat these as the fields of a chunk.

        //  TreeBins
        //    Treebins are pointers to the roots of trees holding a range of
        //    sizes. There are 2 equally spaced treebins for each power of two
        //    from TREE_SHIFT to TREE_SHIFT+16. The last bin holds anything
        //    larger.

        //  Bin maps
        //    There is one bit map for small bins ("smallmap") and one for
        //    treebins ("treemap).  Each bin sets its bit when non-empty, and
        //    clears the bit when empty.  Bit operations are then used to avoid
        //    bin-by-bin searching -- nearly all "search" is done without ever
        //    looking at bins that won't be selected.  The bit maps
        //    conservatively use 32 bits per map word, even if on 64bit system.
        //    For a good description of some of the bit-based techniques used
        //    here, see Henry S. Warren Jr's book "Hacker's Delight" (and
        //    supplement at http://hackersdelight.org/). Many of these are
        //    intended to reduce the branchiness of paths through malloc etc, as
        //    well as to reduce the number of memory locations read or written.

        //  Segments
        //    A list of segments headed by an embedded malloc_segment record
        //    representing the initial space.

        //  Address check support
        //    The least_addr field is the least address ever obtained from
        //    MORECORE or MMAP. Attempted frees and reallocs of any address less
        //    than this are trapped

        //  Magic tag
        //    A cross-check field that should always hold same value as mparams.magic.

        //  Max allowed footprint
        //    The maximum allowed bytes to allocate from system (zero means no limit)

        //  Flags
        //    Bits recording whether to use MMAP or contiguous MORECORE

        //  Statistics
        //    Each space keeps track of current and maximum system memory
        //    obtained via MORECORE or MMAP.

        //  Trim support
        //    Fields holding the amount of unused topmost memory that should trigger
        //    trimming, and a counter to force periodic scanning to release unused
        //    non-topmost segments.

        // Bin types, widths and sizes
        const size_t NSMALLBINS = 32U;
        const size_t NTREEBINS = 32U;
        const size_t SMALLBIN_SHIFT = 3U;
        const size_t SMALLBIN_WIDTH = (int)SIZE_T_ONE << (int)SMALLBIN_SHIFT;
        const size_t TREEBIN_SHIFT = 8U;
        const size_t MIN_LARGE_SIZE = (int)SIZE_T_ONE << (int)TREEBIN_SHIFT;
        const size_t MAX_SMALL_SIZE = MIN_LARGE_SIZE - SIZE_T_ONE;
        static size_t MAX_SMALL_REQUEST => MAX_SMALL_SIZE - CHUNK_ALIGN_MASK - CHUNK_OVERHEAD;

        // Originally called malloc_state, mstate, and mspace
        uint smallmap;
        uint treemap;
        size_t dvsize;
        size_t topsize;
        byte* least_addr;
        mchunk* dv;
        mchunk* top;
        size_t trim_check;
        size_t release_checks;
        size_t magic;
        mchunk** smallbins;
        tchunk** treebins;
        size_t footprint;
        size_t max_footprint;
        flag_t mflags;
        msegment* seg;
        int malloc_corruption_error_count;

        /// <summary>
        /// Returns the number of malloc segments, which represents
        /// the number of discontiguous memory regions. 
        /// </summary>
        public int SegmentCount
        {
            get
            {
                int count = 0;
                var segment = seg;
                while (segment != null)
                {
                    count++;
                    segment = segment->next;
                }
                return count;
            }
        }

        //  Supported pointer/size_t representation:       4 or 8 bytes
        //  Alignment:                                     8 bytes (minimum)
        //       This suffices for nearly all current machines and C compilers.
        //       However, you can define MALLOC_ALIGNMENT to be wider than this
        //       if necessary (up to 128bytes), at the expense of using more space.
        const size_t MALLOC_ALIGNMENT = 8;

        //  Minimum overhead per allocated chunk:   4 bytes (if 4 byte pointer sizes)
        //                                          8 bytes (if 8 byte pointer sizes)

        //  Minimum allocated size: 4-byte ptrs:  16 bytes    (including overhead)
        //                          8-byte ptrs:  32 bytes    (including overhead)

        //       Even a request for zero bytes (i.e., malloc(0)) returns a
        //       pointer to something of the minimum allocatable size.
        //       The maximum overhead wastage (i.e., number of extra bytes
        //       allocated than were requested in malloc) is less than or equal
        //       to the minimum size

        //  Thread-safety: NOT thread-safe

        // Overview of algorithms

        //  In most ways, this malloc is a best-fit allocator. Generally, it
        //  chooses the best-fitting existing chunk for a request, with ties
        //  broken in approximately least-recently-used order. (This strategy
        //  normally maintains low fragmentation.) However, for requests less
        //  than 256bytes, it deviates from best-fit when there is not an
        //  exactly fitting available chunk by preferring to use space adjacent
        //  to that used for the previous small request, as well as by breaking
        //  ties in approximately most-recently-used order. (These enhance
        //  locality of series of small allocations.)  

        //  All operations (except malloc_stats and mallinfo) have execution
        //  times that are bounded by a constant factor of the number of bits in
        //  a size_t, not counting any clearing in calloc or copying in realloc,
        //  or actions surrounding MORECORE and MMAP that have times
        //  proportional to the number of non-contiguous regions returned by
        //  system allocation routines, which is often just 1. In real-time
        //  applications, you can optionally suppress segment traversals using
        //  NO_SEGMENT_TRAVERSAL, which assures bounded execution even when
        //  system allocators return non-contiguous spaces, at the typical
        //  expense of carrying around more memory and increased fragmentation.

        //  For a longer but out of date high-level description, see
        //     http://gee.cs.oswego.edu/dl/html/malloc.html


        // NO_SEGMENT_TRAVERSAL       default: 0
        //  If non-zero, suppresses traversals of memory segments
        //  returned by CALL_MMAP. This disables
        //  merging of segments that are contiguous, and selectively
        //  releasing them to the OS if unused, but bounds execution times.

        protected bool NO_SEGMENT_TRAVERSAL = false;

        // DEFAULT_GRANULARITY        default: page size (64K)
        //  The unit for allocating and deallocating memory from the system.  On
        //  most systems with contiguous MORECORE, there is no reason to
        //  make this more than a page. However, systems with MMAP tend to
        //  either require or encourage larger granularities.  You can increase
        //  this value to prevent system allocation functions to be called so
        //  often, especially if they are slow.  The value must be at least one
        //  page and must be a power of two.  Setting to 0 causes initialization
        //  to either page size or win32 region size.  (Note: In previous
        //  versions of malloc, the equivalent of this option was called
        //  "TOP_PAD")
        const size_t DEFAULT_GRANULARITY = 65536;

        // DEFAULT_TRIM_THRESHOLD    default: 2MB
        //      Also settable using mallopt(M_TRIM_THRESHOLD, x)
        //  The maximum amount of unused top-most memory to keep before
        //  releasing via malloc_trim in free().  Automatic trimming is mainly
        //  useful in long-lived programs using contiguous MORECORE.  Because
        //  trimming via sbrk can be slow on some systems, and can sometimes be
        //  wasteful (in cases where programs immediately afterward allocate
        //  more large chunks) the value should be high enough so that your
        //  overall system performance would improve by releasing this much
        //  memory.  As a rough guide, you might set to a value close to the
        //  average size of a process (program) running on your system.
        //  Releasing this much memory would allow such a process to run in
        //  memory.  Generally, it is worth tuning trim thresholds when a
        //  program undergoes phases where several large chunks are allocated
        //  and released in ways that can reuse each other's storage, perhaps
        //  mixed with phases where there are no such chunks at all. The trim
        //  value must be greater than page size to have any useful effect.  To
        //  disable trimming completely, you can set to MAX_SIZE_T. Note that the trick
        //  some people use of mallocing a huge space and then freeing it at
        //  program startup, in an attempt to reserve system memory, doesn't
        //  have the intended effect under automatic trimming, since that memory
        //  will immediately be returned to the system.
        const size_t DEFAULT_TRIM_THRESHOLD = 2 * 1024 * 1024;


        // MAX_RELEASE_CHECK_RATE   default: 4095
        //  The number of consolidated frees between checks to release
        //  unused segments when freeing. When using non-contiguous segments,
        //  especially with multiple mspaces, checking only for topmost space
        //  doesn't always suffice to trigger trimming. To compensate for this,
        //  free() will, with a period of MAX_RELEASE_CHECK_RATE (or the
        //  current number of segments, if greater) try to release unused
        //  segments to the OS when freeing chunks that result in
        //  consolidation. The best value for this parameter is a compromise
        //  between slowing down frees with relatively costly checks that
        //  rarely trigger versus holding on to unused memory. To effectively
        //  disable, set to MAX_SIZE_T. This may lead to a very slight speed
        //  improvement at the expense of carrying around more memory.
        protected size_t MAX_RELEASE_CHECK_RATE = 4095;


        // The maximum possible size_t value has all bits set
        const size_t MAX_SIZE_T = ~(size_t)0;

        // ------------------- size_t and alignment properties --------------------

        // The byte and bit size of a size_t 
        static size_t SIZE_T_SIZE => (size_t)sizeof(IntPtr);
        static size_t SIZE_T_BITSIZE => (size_t)sizeof(IntPtr) << 3;

        // Some constants coerced to size_t
        const size_t SIZE_T_ZERO = 0;
        const size_t SIZE_T_ONE = 1;
        const size_t SIZE_T_TWO = 2;
        const size_t SIZE_T_FOUR = 4;
        static size_t TWO_SIZE_T_SIZES => SIZE_T_SIZE << 1;
        static size_t FOUR_SIZE_T_SIZES => SIZE_T_SIZE << 2;

        // The bit mask value corresponding to MALLOC_ALIGNMENT
        const size_t CHUNK_ALIGN_MASK = MALLOC_ALIGNMENT - SIZE_T_ONE;

        // True if address a has acceptable alignment
        static bool is_aligned(void* a) { return ((size_t)a & (CHUNK_ALIGN_MASK)) == 0; }

        // the number of bytes to offset an address to align it
        static size_t align_offset(void* a)
        {
            return ((size_t)a & CHUNK_ALIGN_MASK) == 0 ? 0
                    : (MALLOC_ALIGNMENT - ((size_t)a & CHUNK_ALIGN_MASK)) & CHUNK_ALIGN_MASK;
        }

        // -----------------------  Chunk representations ------------------------

        //  (The following includes lightly edited explanations by Colin Plumb.)

        //  The malloc_chunk declaration below is misleading (but accurate and
        //  necessary).  It declares a "view" into memory allowing access to
        //  necessary fields at known offsets from a given base.

        //  Chunks of memory are maintained using a `boundary tag' method as
        //  originally described by Knuth.  (See the paper by Paul Wilson
        //  ftp://ftp.cs.utexas.edu/pub/garbage/allocsrv.ps for a survey of such
        //  techniques.)  Sizes of free chunks are stored both in the front of
        //  each chunk and at the end.  This makes consolidating fragmented
        //  chunks into bigger chunks fast.  The head fields also hold bits
        //  representing whether chunks are free or in use.

        //  Here are some pictures to make it clearer.  They are "exploded" to
        //  show that the state of a chunk can be thought of as extending from
        //  the high 31 bits of the head field of its header through the
        //  prev_foot and PINUSE_BIT bit of the following chunk header.

        //  A chunk that's in use looks like:

        //   chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //           | Size of previous chunk (if P = 0)                             |
        //           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |P|
        //         | Size of this chunk                                         1| +-+
        //   mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //         |                                                               |
        //         +-                                                             -+
        //         |                                                               |
        //         +-                                                             -+
        //         |                                                               :
        //         +-      size - sizeof(size_t) available payload bytes          -+
        //         :                                                               |
        // chunk-> +-                                                             -+
        //         |                                                               |
        //         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |1|
        //       | Size of next chunk (may or may not be in use)               | +-+
        // mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        //    And if it's free, it looks like this:

        //   chunk-> +-                                                             -+
        //           | User payload (must be in use, or we would have merged!)       |
        //           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |P|
        //         | Size of this chunk                                         0| +-+
        //   mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //         | Next pointer                                                  |
        //         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //         | Prev pointer                                                  |
        //         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //         |                                                               :
        //         +-      size - sizeof(struct chunk) unused bytes               -+
        //         :                                                               |
        // chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //         | Size of this chunk                                            |
        //         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |0|
        //       | Size of next chunk (must be in use, or we would have merged)| +-+
        // mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //       |                                                               :
        //       +- User payload                                                -+
        //       :                                                               |
        //       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //                                                                     |0|
        //                                                                     +-+
        //  Note that since we always merge adjacent free chunks, the chunks
        //  adjacent to a free chunk must be in use.

        //  Given a pointer to a chunk (which can be derived trivially from the
        //  payload pointer) we can, in O(1) time, find out whether the adjacent
        //  chunks are free, and if so, unlink them from the lists that they
        //  are on and merge them with the current chunk.

        //  Chunks always begin on even word boundaries, so the mem portion
        //  (which is returned to the user) is also on an even word boundary, and
        //  thus at least double-word aligned.

        //  The P (PINUSE_BIT) bit, stored in the unused low-order bit of the
        //  chunk size (which is always a multiple of two words), is an in-use
        //  bit for the *previous* chunk.  If that bit is *clear*, then the
        //  word before the current chunk size contains the previous chunk
        //  size, and can be used to find the front of the previous chunk.
        //  The very first chunk allocated always has this bit set, preventing
        //  access to non-existent (or non-owned) memory. If pinuse is set for
        //  any given chunk, then you CANNOT determine the size of the
        //  previous chunk, and might even get a memory addressing fault when
        //  trying to do so.

        //  The C (CINUSE_BIT) bit, stored in the unused second-lowest bit of
        //  the chunk size redundantly records whether the current chunk is
        //  inuse (unless the chunk is mmapped). This redundancy enables usage
        //  checks within free and realloc, and reduces indirection when freeing
        //  and consolidating chunks.

        //  Each freshly allocated chunk must have both cinuse and pinuse set.
        //  That is, each allocated chunk borders either a previously allocated
        //  and still in-use chunk, or the base of its memory arena. This is
        //  ensured by making all allocations from the `lowest' part of any
        //  found chunk.  Further, no free chunk physically borders another one,
        //  so each free chunk is known to be preceded and followed by either
        //  inuse chunks or the ends of memory.

        //  Note that the `foot' of the current chunk is actually represented
        //  as the prev_foot of the NEXT chunk. This makes it easier to
        //  deal with alignments etc but can be very confusing when trying
        //  to extend or adapt this code.

        //  The exceptions to all this are

        //     1. The special chunk `top' is the top-most available chunk (i.e.,
        //        the one bordering the end of available memory). It is treated
        //        specially.  Top is never included in any bin, is used only if
        //        no other chunk is available, and is released back to the
        //        system if it is very large (see M_TRIM_THRESHOLD).  In effect,
        //        the top chunk is treated as larger (and thus less well
        //        fitting) than any other available chunk.  The top chunk
        //        doesn't update its trailing size field since there is no next
        //        contiguous chunk that would have to index off it. However,
        //        space is still allocated for it (TOP_FOOT_SIZE) to enable
        //        separation or merging when space is extended.

        //     3. Chunks allocated via mmap, have both cinuse and pinuse bits
        //        cleared in their head fields.  Because they are allocated
        //        one-by-one, each must carry its own prev_foot field, which is
        //        also used to hold the offset this chunk has within its mmapped
        //        region, which is needed to preserve alignment. Each mmapped
        //        chunk is trailed by the first two fields of a fake next-chunk
        //        for sake of usage checks.

        /// Originally malloc_chunk, now mchunk
        public struct mchunk
        {
            public IntPtr prev_foot_ptr; // Size of previous chunk (if free).
            public IntPtr head_ptr;      // Size and inuse bits.
            public mchunk* fd;         // double links -- used only if free.
            public mchunk* bk;

            public size_t prev_foot
            {
                get { return (size_t)prev_foot_ptr; }
                set { prev_foot_ptr = (IntPtr)value; }
            }
            public size_t head
            {
                get { return (size_t)head_ptr; }
                set { head_ptr = (IntPtr)value; }
            }
        };

        static bool cinuse(mchunk* p) => (p->head & CINUSE_BIT) != 0;
        static bool pinuse(mchunk* p) => (p->head & PINUSE_BIT) != 0;
        static bool flag4inuse(mchunk* p) => (p->head & FLAG4_BIT) != 0;
        static bool is_inuse(mchunk* p) => (p->head & INUSE_BITS) != PINUSE_BIT;
        static bool is_mmapped(mchunk* p) => (p->head & INUSE_BITS) == 0;
        static size_t chunksize(mchunk* p) => p->head & ~FLAG_BITS;
        static void clear_pinuse(mchunk* p) => p->head &= ~PINUSE_BIT;
        static void set_flag4(mchunk* p) => p->head |= FLAG4_BIT;
        static void clear_flag4(mchunk* p) => p->head &= ~FLAG4_BIT;
        static mchunk* chunk_plus_offset(mchunk* p, size_t s) => (mchunk*)((byte*)p + s);
        static mchunk* chunk_minus_offset(mchunk* p, size_t s) => (mchunk*)((byte*)p - s);
        static mchunk* next_chunk(mchunk* p) => (mchunk*)((byte*)p + (p->head & ~FLAG_BITS));
        static mchunk* prev_chunk(mchunk* p) => (mchunk*)((byte*)p - (p->prev_foot));
        static bool next_pinuse(mchunk* p) => ((next_chunk(p)->head) & PINUSE_BIT) != 0;
        static size_t get_foot(mchunk* p, size_t s) => (((mchunk*)((byte*)p + s))->prev_foot);
        static void set_foot(mchunk* p, size_t s) => ((mchunk*)((byte*)p + s))->prev_foot = s;
        static void set_size_and_pinuse_of_free_chunk(mchunk* p, size_t s) { p->head = s | PINUSE_BIT; set_foot(p, s); }
        static void set_free_with_pinuse(mchunk* p, size_t s, mchunk* n) { clear_pinuse(n); set_size_and_pinuse_of_free_chunk(p, s); }

        // ------------------- Chunks sizes and alignments -----------------------

        static size_t CHUNK_OVERHEAD => SIZE_T_SIZE;
        static size_t MCHUNK_SIZE => (size_t)sizeof(mchunk);
        static size_t MIN_CHUNK_SIZE => (MCHUNK_SIZE + CHUNK_ALIGN_MASK) & ~CHUNK_ALIGN_MASK;
        static size_t MAX_REQUEST => unchecked((size_t)(-(int)MIN_CHUNK_SIZE) << 2);
        static size_t MIN_REQUEST => MIN_CHUNK_SIZE - CHUNK_OVERHEAD - SIZE_T_ONE;

        // conversion from malloc headers to user pointers, and back
        static void* chunk2mem(void* p) => ((void*)((byte*)p + TWO_SIZE_T_SIZES));
        static mchunk* mem2chunk(void* mem) => ((mchunk*)((byte*)mem - TWO_SIZE_T_SIZES));
        static mchunk* align_as_chunk(byte* A) => (mchunk*)(A + align_offset(chunk2mem(A)));
        static size_t pad_request(size_t req) => ((req) + CHUNK_OVERHEAD + CHUNK_ALIGN_MASK) & ~CHUNK_ALIGN_MASK;
        static size_t request2size(size_t req) => ((req) < MIN_REQUEST) ? MIN_CHUNK_SIZE : pad_request(req);

        // ------------------ Operations on head and foot fields -----------------

        //  The head field of a chunk is or'ed with PINUSE_BIT when previous
        //  adjacent chunk in use, and or'ed with CINUSE_BIT if this chunk is in
        //  use, unless mmapped, in which case both bits are cleared.
        //  FLAG4_BIT is not used by this malloc, but might be useful in extensions.

        const size_t PINUSE_BIT = SIZE_T_ONE;
        const size_t CINUSE_BIT = SIZE_T_TWO;
        const size_t FLAG4_BIT = SIZE_T_FOUR;
        const size_t INUSE_BITS = PINUSE_BIT | CINUSE_BIT;
        const size_t FLAG_BITS = PINUSE_BIT | CINUSE_BIT | FLAG4_BIT;

        // Head value for fenceposts
        static size_t FENCEPOST_HEAD => INUSE_BITS | SIZE_T_SIZE;

        // Get the internal overhead associated with chunk p

        // ---------------------- Overlaid data structures -----------------------

        //  When chunks are not in use, they are treated as nodes of either
        //  lists or trees.

        //  "Small"  chunks are stored in circular doubly-linked lists, and look
        //  like this:

        //    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             Size of previous chunk                            |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //    `head:' |             Size of chunk, in bytes                         |P|
        //      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             Forward pointer to next chunk in list             |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             Back pointer to previous chunk in list            |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             Unused space (may be 0 bytes long)                .
        //            .                                                               .
        //            .                                                               |
        //nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //    `foot:' |             Size of chunk, in bytes                           |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        //  Larger chunks are kept in a form of bitwise digital trees (aka
        //  tries) keyed on chunksizes.  Because malloc_tree_chunks are only for
        //  free chunks greater than 256 bytes, their size doesn't impose any
        //  constraints on user chunk sizes.  Each node looks like:

        //    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             Size of previous chunk                            |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //    `head:' |             Size of chunk, in bytes                         |P|
        //      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             Forward pointer to next chunk of same size        |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             Back pointer to previous chunk of same size       |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             Pointer to left child (child[0])                  |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             Pointer to right child (child[1])                 |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             Pointer to parent                                 |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             bin index of this chunk                           |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //            |             Unused space                                      .
        //            .                                                               |
        //nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //    `foot:' |             Size of chunk, in bytes                           |
        //            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        //  Each tree holding treenodes is a tree of unique chunk sizes.  Chunks
        //  of the same size are arranged in a circularly-linked list, with only
        //  the oldest chunk (the next to be used, in our FIFO ordering)
        //  actually in the tree.  (Tree members are distinguished by a non-null
        //  parent pointer.)  If a chunk with the same size an an existing node
        //  is inserted, it is linked off the existing node using pointers that
        //  work in the same way as fd/bk pointers of small chunks.

        //  Each tree contains a power of 2 sized range of chunk sizes (the
        //  smallest is 0x100 <= x < 0x180), which is is divided in half at each
        //  tree level, with the chunks in the smaller half of the range (0x100
        //  <= x < 0x140 for the top nose) in the left subtree and the larger
        //  half (0x140 <= x < 0x180) in the right subtree.  This is, of course,
        //  done by inspecting individual bits.

        //  Using these rules, each node's left subtree contains all smaller
        //  sizes than its right subtree.  However, the node at the root of each
        //  subtree has no particular ordering relationship to either.  (The
        //  dividing line between the subtree sizes is based on trie relation.)
        //  If we remove the last chunk of a given size from the interior of the
        //  tree, we need to replace it with a leaf node.  The tree ordering
        //  rules permit a node to be replaced by any leaf below it.

        //  The smallest chunk in a tree (a common operation in a best-fit
        //  allocator) can be found by walking a path to the leftmost leaf in
        //  the tree.  Unlike a usual binary tree, where we follow left child
        //  pointers until we reach a null, here we follow the right child
        //  pointer any time the left one is null, until we reach a leaf with
        //  both child pointers null. The smallest chunk in the tree will be
        //  somewhere along that path.

        //  The worst case number of steps to add, find, or remove a node is
        //  bounded by the number of bits differentiating chunks within
        //  bins. Under current bin calculations, this ranges from 6 up to 21
        //  (for 32 bit sizes) or up to 53 (for 64 bit sizes). The typical case
        //  is of course much better.

        /// <summary>
        /// Originally malloc_tree_chunk, now tchunk
        /// </summary>
        public struct tchunk
        {
            // The first four fields must be compatible with mchunk
            public IntPtr prev_foot_ptr;
            public IntPtr head_ptr;
            public tchunk* fd;
            public tchunk* bk;

            public tchunk* child0;
            public tchunk* child1;
            public tchunk* parent;
            public uint index;

            public size_t prev_foot
            {
                get { return (size_t)prev_foot_ptr; }
                set { prev_foot_ptr = (IntPtr)value; }
            }
            public size_t head
            {
                get { return (size_t)head_ptr; }
                set { head_ptr = (IntPtr)value; }
            }

        };

        static mchunk* chunk_plus_offset(tchunk* p, size_t s) => (mchunk*)((byte*)p + s);
        static bool is_inuse(tchunk* p) => (p->head & INUSE_BITS) != PINUSE_BIT;
        static size_t chunksize(tchunk* p) => p->head & ~FLAG_BITS;
        static tchunk* next_chunk(tchunk* p) => (tchunk*)((byte*)p + (p->head & ~FLAG_BITS));
        static tchunk* prev_chunk(tchunk* p) => (tchunk*)((byte*)p - (p->prev_foot));
        static bool next_pinuse(tchunk* p) => ((next_chunk(p)->head) & PINUSE_BIT) != 0;
        static tchunk* leftmost_child(tchunk* t) => t->child0 != null ? t->child0 : t->child1;


        // ----------------------------- Segments --------------------------------

        //  Each malloc space may include non-contiguous segments, held in a
        //  list headed by an embedded malloc_segment record representing the
        //  top-most space. Segments also include flags holding properties of
        //  the space. Large chunks that are directly allocated by mmap are not
        //  included in this list. They are instead independently created and
        //  destroyed without otherwise keeping track of them.

        //  Segment management mainly comes into play for spaces allocated by
        //  MMAP.  Any call to MMAP might or might not return memory that is
        //  adjacent to an existing segment.  MORECORE normally contiguously
        //  extends the current space, so this space is almost always adjacent,
        //  which is simpler and faster to deal with. (This is why MORECORE is
        //  used preferentially to MMAP when both are available -- see
        //  sys_alloc.)  When allocating using MMAP, we don't use any of the
        //  hinting mechanisms (inconsistently) supported in various
        //  implementations of unix mmap, or distinguish reserving from
        //  committing memory. Instead, we just ask for space, and exploit
        //  contiguity when we get it.  It is probably possible to do
        //  better than this on some systems, but no general scheme seems
        //  to be significantly better.

        //  Management entails a simpler variant of the consolidation scheme
        //  used for chunks to reduce fragmentation -- new adjacent memory is
        //  normally prepended or appended to an existing segment. However,
        //  there are limitations compared to chunk consolidation that mostly
        //  reflect the fact that segment processing is relatively infrequent
        //  (occurring only when getting memory from system) and that we
        //  don't expect to have huge numbers of segments:

        //  * Segments are not indexed, so traversal requires linear scans.  (It
        //    would be possible to index these, but is not worth the extra
        //    overhead and complexity for most programs on most platforms.)
        //  * New segments are only appended to old ones when holding top-most
        //    memory; if they cannot be prepended to others, they are held in
        //    different segments.

        //  Except for the top-most segment of an mstate, each segment record
        //  is kept at the tail of its segment. Segments are added by pushing
        //  segment records onto the list headed by &mstate.seg for the
        //  containing mstate.

        //  Segment flags control allocation/merge/deallocation policies:
        //  * If EXTERN_BIT set, then we did not allocate this segment,
        //    and so should not try to deallocate or merge with others.
        //    (This currently holds only for the initial segment passed
        //    into create_mspace_with_base.)
        //  * If USE_MMAP_BIT set, the segment may be merged with
        //    other surrounding mmapped segments and trimmed/de-allocated
        //    using munmap.
        //  * If neither bit is set, then the segment was obtained using
        //    MORECORE so can be merged with surrounding MORECORE'd segments
        //    and deallocated/trimmed using MORECORE with negative arguments.


        /// <summary>
        /// malloc_segment
        /// </summary>
        struct msegment
        {
            public byte* baseAddr;   // base address
            public size_t size;       // allocated size
            public msegment* next;       // ptr to next segment
            public flag_t sflags;     // mmap and extern flag
        };

        static bool is_mmapped_segment(msegment* s) => (s->sflags & flag_t.USE_MMAP_BIT) != 0;
        static bool is_extern_segment(msegment* s) => ((s)->sflags & flag_t.EXTERN_BIT) != 0;

        // Everything is mmaped in this malloc, so these flags are mostly unused
        enum flag_t
        {
            USE_MMAP_BIT = 1,
            EXTERN_BIT = 8,
        }


        //  malloc_params holds global properties, including those that can be
        //  dynamically set using mallopt. There is a single instance, mparams,
        //  initialized in init_mparams. Note that the non-zeroness of "magic"
        //  also serves as an initialization flag.

        struct malloc_params
        {
            public size_t magic;
            public size_t page_size;
            public size_t granularity;
            public size_t trim_threshold;
            public flag_t default_mflags;
        };

        malloc_params mparams;

        // Ensure mparams initialized
        void ensure_initialization() { if (mparams.magic == 0) init_mparams(); }

        bool is_initialized() { return top != null; }

        // -------------------------- system alloc setup -------------------------

        // Operations on mflags

        bool use_mmap() => (mflags & flag_t.USE_MMAP_BIT) != 0;
        void enable_mmap() => mflags |= flag_t.USE_MMAP_BIT;

        // page-align a size 
        size_t page_align(size_t s)
            => (s + (mparams.page_size - SIZE_T_ONE)) & ~(mparams.page_size - SIZE_T_ONE);


        // granularity-align a size
        size_t granularity_align(size_t s)
            => ((s) + (mparams.granularity - SIZE_T_ONE)) & ~(mparams.granularity - SIZE_T_ONE);

        size_t mmap_align(size_t s) => granularity_align(s);

        // For sys_alloc, enough padding to ensure can malloc request on success
        size_t SYS_ALLOC_PADDING => TOP_FOOT_SIZE + MALLOC_ALIGNMENT;

        bool is_page_aligned(size_t s) => (s & (mparams.page_size - SIZE_T_ONE)) == 0;

        bool is_granularity_aligned(size_t s) => (s & (mparams.granularity - SIZE_T_ONE)) == 0;

        //  True if segment S holds address A
        static bool segment_holds(msegment* s, void* a) => a >= s->baseAddr && a < s->baseAddr + s->size;

        // Return segment holding given address
        msegment* segment_holding(byte* addr)
        {
            msegment* sp = seg;
            for (; ; )
            {
                if (addr >= sp->baseAddr && addr < sp->baseAddr + sp->size)
                    return sp;
                if ((sp = sp->next) == null)
                    return null;
            }
        }

        // Return true if segment contains a segment link
        bool has_segment_link(msegment* ss)
        {
            msegment* sp = seg;
            for (; ; )
            {
                if ((byte*)sp >= ss->baseAddr && (byte*)sp < ss->baseAddr + ss->size)
                    return true;
                if ((sp = sp->next) == null)
                    return false;
            }
        }

        bool should_trim(size_t s) => s > trim_check;

        //  TOP_FOOT_SIZE is padding at the end of a segment, including space
        //  that may be needed to place segment records and fenceposts when new
        //  noncontiguous segments are added.
        static size_t TOP_FOOT_SIZE
            => align_offset(chunk2mem((mchunk*)0)) + pad_request((uint)sizeof(msegment)) + MIN_CHUNK_SIZE;

        // -------------------------- Debugging setup ----------------------------

        [Conditional("DEBUG")] void check_free_chunk(mchunk* p) { do_check_free_chunk(p); }
        [Conditional("DEBUG")] void check_inuse_chunk(mchunk* p) { do_check_inuse_chunk(p); }
        [Conditional("DEBUG")] void check_malloced_chunk(void* mem, size_t s) { do_check_malloced_chunk(mem, s); }
        [Conditional("DEBUG")] void check_top_chunk(mchunk* p) { do_check_top_chunk(p); }

        // ---------------------------- Indexing Bins ----------------------------

        static bool is_small(size_t s) => (s >> (int)SMALLBIN_SHIFT) < NSMALLBINS;
        static uint small_index(size_t s) => (uint)(s >> (int)SMALLBIN_SHIFT);
        static size_t small_index2size(size_t i) => i << (int)SMALLBIN_SHIFT;
        static size_t MIN_SMALL_INDEX => small_index(MIN_CHUNK_SIZE);

        // addressing by index. See above about smallbin repositioning
        mchunk* smallbin_at(uint i) => (mchunk*)&(smallbins[(i) << 1]);
        tchunk** treebin_at(uint i) => (tchunk**)&(treebins[i]);

        // Find tree index for size S
        static uint compute_tree_index(size_t s)
        {
            size_t x = s >> (int)TREEBIN_SHIFT;
            if (x == 0)
                return 0;
            if (x > 0xFFFF)
                return (int)NTREEBINS - 1;
            uint y = (uint)x;
            uint n = ((y - 0x100) >> 16) & 8;
            uint k = (((y <<= (int)n) - 0x1000) >> 16) & 4;
            n += k;
            n += k = (((y <<= (int)k) - 0x4000) >> 16) & 2;
            k = 14 - n + ((y <<= (int)k) >> 15);
            return (uint)((k << 1) + ((s >> (int)(k + TREEBIN_SHIFT - 1)) & 1));
        }


        // Bit representing maximum resolved size in a treebin at i
        static size_t bit_for_tree_index(size_t i)
            => i == NTREEBINS - 1 ? SIZE_T_BITSIZE - 1 : (i >> 1) + TREEBIN_SHIFT - 2;

        // Shift placing maximum resolved bit in a treebin at i as sign bit
        static int leftshift_for_tree_index(size_t i)
            => (int)(i == NTREEBINS - 1 ? 0 : SIZE_T_BITSIZE - SIZE_T_ONE - ((i >> 1) + TREEBIN_SHIFT - 2));

        // The size of the smallest chunk held in bin with index i
        static size_t minsize_for_tree_index(size_t i)
            => SIZE_T_ONE << (int)((i >> 1) + TREEBIN_SHIFT) | ((i & SIZE_T_ONE)) << (int)((i >> 1) + TREEBIN_SHIFT - 1);


        // ------------------------ Operations on bin maps -----------------------

        // bit corresponding to given index
        static uint idx2bit(uint i) => 1u << (int)i;

        // Mark/Clear bits with given index
        uint mark_smallmap(uint i) => smallmap |= idx2bit(i);
        uint clear_smallmap(uint i) => smallmap &= ~idx2bit(i);
        bool smallmap_is_marked(uint i) => (smallmap & idx2bit(i)) != 0;

        uint mark_treemap(uint i) => treemap |= idx2bit(i);
        uint clear_treemap(uint i) => treemap &= ~idx2bit(i);
        bool treemap_is_marked(uint i) => (treemap & idx2bit(i)) != 0;

        // isolate the least set bit of a bitmap
        static uint least_bit(uint x) => x & (uint)(-(int)x);

        // mask with all bits to left of least bit of x on
        static uint left_bits(uint x) => (x << 1) | (uint)(-(int)(x << 1));

        // mask with all bits to left of or equal to least bit of x on
        static uint same_or_left_bits(uint x) => x | (uint)(-(int)x);

        // index corresponding to given bit. 
        static uint compute_bit2idx(uint x)
        {
            uint y = x - 1;
            uint k = y >> (16 - 4) & 16;
            uint n = k;
            y >>= (int)k;
            n += k = y >> (8 - 3) & 8; y >>= (int)k;
            n += k = y >> (4 - 2) & 4; y >>= (int)k;
            n += k = y >> (2 - 1) & 2; y >>= (int)k;
            n += k = y >> (1 - 0) & 1; y >>= (int)k;
            return n + y;
        }



        // ----------------------- Runtime Check Support -------------------------

        //  For security, the main invariant is that malloc/free/etc never
        //  writes to a static address other than malloc_state, unless static
        //  malloc_state itself has been corrupted, which cannot occur via
        //  malloc (because of these checks). In essence this means that we
        //  believe all pointers, sizes, maps etc held in malloc_state, but
        //  check all of those linked or offsetted from other embedded data
        //  structures.  These checks are interspersed with main code in a way
        //  that tends to minimize their run-time cost.

        //  In addition to range checking, we also [...]
        //  always dynamically check addresses of all offset chunks (previous,
        //  next, etc). This turns out to be cheaper than relying on hashes.


        // Check if address a is at least as high as any from MORECORE or MMAP
        bool ok_address(void* a) => a >= least_addr;
        static bool ok_next(tchunk* p, mchunk* n) => (byte*)p < (byte*)n;
        static bool ok_next(mchunk* p, mchunk* n) => (byte*)p < (byte*)n;
        static bool ok_inuse(mchunk* p) => is_inuse(p);
        static bool ok_pinuse(mchunk* p) => pinuse(p);


        bool ok_magic() => magic == mparams.magic;

        static bool RTCHECK(bool e) => e;

        void set_inuse(mchunk* p, size_t s)
        {
            p->head = (p->head & PINUSE_BIT) | s | CINUSE_BIT;
            ((mchunk*)(((byte*)p) + s))->head |= PINUSE_BIT;
        }

        void set_inuse_and_pinuse(mchunk* p, size_t s)
        {
            p->head = s | PINUSE_BIT | CINUSE_BIT;
            ((mchunk*)(((byte*)p) + s))->head |= PINUSE_BIT;
        }

        void set_inuse_and_pinuse(tchunk* p, size_t s)
        {
            p->head = s | PINUSE_BIT | CINUSE_BIT;
            ((mchunk*)(((byte*)p) + s))->head |= PINUSE_BIT;
        }

        void set_size_and_pinuse_of_inuse_chunk(mchunk* p, size_t s)
        {
            p->head = s | PINUSE_BIT | CINUSE_BIT;
        }

        // ---------------------------- setting mparams --------------------------

        // Initialize mparams
        int init_mparams()
        {
            // Sanity-check configuration:
            // size_t must be unsigned and as wide as pointer type.
            // ints must be at least 4 bytes.
            // alignment must be at least 8.
            // Alignment, min chunk size, and page size must all be powers of 2.
            size_t psize = (uint)Environment.SystemPageSize;
            size_t gsize = DEFAULT_GRANULARITY != 0 ? DEFAULT_GRANULARITY : psize; // dwAllocationGranularity
            if ((sizeof(size_t) < sizeof(byte*))
                || (MAX_SIZE_T < MIN_CHUNK_SIZE)
                || (sizeof(int) < 4)
                || (MALLOC_ALIGNMENT < 8)
                || ((MALLOC_ALIGNMENT & (MALLOC_ALIGNMENT - SIZE_T_ONE)) != 0)
                || ((MCHUNK_SIZE & (MCHUNK_SIZE - SIZE_T_ONE)) != 0)
                || ((gsize & (gsize - SIZE_T_ONE)) != 0)
                || ((psize & (psize - SIZE_T_ONE)) != 0))
            {
                throw new DlMallocException("Abort: Sanity check failed");
            }

            if (mparams.magic == 0)
            {
                mparams.granularity = gsize;
                mparams.page_size = psize;
                mparams.trim_threshold = DEFAULT_TRIM_THRESHOLD;
                mparams.default_mflags = flag_t.USE_MMAP_BIT;

                size_t magic = (size_t)(Environment.TickCount + DateTime.Now.Ticks + 0x55555555U);
                magic |= 8U;    // ensure nonzero
                magic &= ~7U;   // improve chances of fault for bad values
                mparams.magic = magic;
            }
            return 1;
        }

        // ------------------------- Debugging Support ---------------------------

        static void assert(bool c)
        {
            if (!c) throw new DlMallocException("Malloc assert failed");
        }

        // Check properties of any chunk, whether free, inuse, mmapped etc 
        void do_check_any_chunk(mchunk* p)
        {
            assert(is_aligned(chunk2mem(p)) || p->head == FENCEPOST_HEAD);
            assert(ok_address(p));
        }

        // Check properties of top chunk
        void do_check_top_chunk(mchunk* p)
        {
            msegment* sp = segment_holding((byte*)p);
            size_t sz = p->head & ~INUSE_BITS; // third-lowest bit can be set!
            assert(sp != null);
            assert(is_aligned(chunk2mem(p)) || p->head == FENCEPOST_HEAD);
            assert(ok_address(p));
            assert(sz == topsize);
            assert(sz > 0);
            assert(sz == (size_t)((sp->baseAddr + sp->size) - (byte*)p) - TOP_FOOT_SIZE);
            assert(pinuse(p));
            assert(!pinuse(chunk_plus_offset(p, sz)));
        }

        // Check properties of inuse chunks
        void do_check_inuse_chunk(mchunk* p)
        {
            do_check_any_chunk(p);
            assert(is_inuse(p));
            assert(next_pinuse(p));
            // If not pinuse and not mmapped, previous chunk has OK offset
            assert(pinuse(p) || next_chunk(prev_chunk(p)) == p);
            assert(!is_mmapped(p));
        }

        // Check properties of free chunks
        void do_check_free_chunk(mchunk* p)
        {
            size_t sz = chunksize(p);
            mchunk* next = chunk_plus_offset(p, sz);
            do_check_any_chunk(p);
            assert(!is_inuse(p));
            assert(!next_pinuse(p));
            assert(!is_mmapped(p));
            if (p != dv && p != top)
            {
                if (sz >= MIN_CHUNK_SIZE)
                {
                    assert((sz & CHUNK_ALIGN_MASK) == 0);
                    assert(is_aligned(chunk2mem(p)));
                    assert(next->prev_foot == sz);
                    assert(pinuse(p));
                    assert(next == top || is_inuse(next));
                    assert(p->fd->bk == p);
                    assert(p->bk->fd == p);
                }
                else  // markers are always of size SIZE_T_SIZE
                    assert(sz == SIZE_T_SIZE);
            }
        }

        // Check properties of malloced chunks at the point they are malloced
        void do_check_malloced_chunk(void* mem, size_t s)
        {
            if (mem != null)
            {
                mchunk* p = mem2chunk(mem);
                size_t sz = p->head & ~INUSE_BITS;
                do_check_inuse_chunk(p);
                assert((sz & CHUNK_ALIGN_MASK) == 0);
                assert(sz >= MIN_CHUNK_SIZE);
                assert(sz >= s);
                /* unless mmapped, size is less than MIN_CHUNK_SIZE more than request */
                assert(!is_mmapped(p));
                assert(sz < (s + MIN_CHUNK_SIZE));
            }
        }

        // Check a tree and its subtrees.
        void do_check_tree(tchunk* t)
        {
            tchunk* head = null;
            tchunk* u = t;
            uint tindex = t->index;
            size_t tsize = chunksize(t);
            uint idx = compute_tree_index(tsize);
            assert(tindex == idx);
            assert(tsize >= MIN_LARGE_SIZE);
            assert(tsize >= minsize_for_tree_index(idx));
            assert((idx == NTREEBINS - 1) || (tsize < minsize_for_tree_index((idx + 1))));

            do
            {
                // traverse through chain of same-sized nodes
                do_check_any_chunk(((mchunk*)u));
                assert(u->index == tindex);
                assert(chunksize(u) == tsize);
                assert(!is_inuse(u));
                assert(!next_pinuse(u));
                assert(u->fd->bk == u);
                assert(u->bk->fd == u);
                if (u->parent == null)
                {
                    assert(u->child0 == null);
                    assert(u->child1 == null);
                }
                else
                {
                    assert(head == null); // only one node on chain has parent
                    head = u;
                    assert(u->parent != u);
                    assert(u->parent->child0 == u ||
                            u->parent->child1 == u ||
                            *((tchunk**)(u->parent)) == u);
                    if (u->child0 != null)
                    {
                        assert(u->child0->parent == u);
                        assert(u->child0 != u);
                        do_check_tree(u->child0);
                    }
                    if (u->child1 != null)
                    {
                        assert(u->child1->parent == u);
                        assert(u->child1 != u);
                        do_check_tree(u->child1);
                    }
                    if (u->child0 != null && u->child1 != null)
                    {
                        assert(chunksize(u->child0) < chunksize(u->child1));
                    }
                }
                u = u->fd;
            } while (u != t);
            assert(head != null);
        }

        //  Check all the chunks in a treebin. 
        void do_check_treebin(uint i)
        {
            tchunk** tb = treebin_at(i);
            tchunk* t = *tb;
            bool empty = (treemap & (1U << (int)i)) == 0;
            if (t == null)
                assert(empty);
            if (!empty)
                do_check_tree(t);
        }

        //  Check all the chunks in a smallbin.
        void do_check_smallbin(uint i)
        {
            mchunk* b = smallbin_at(i);
            mchunk* p = b->bk;
            bool empty = (smallmap & (1U << (int)i)) == 0;
            if (p == b)
                assert(empty);
            if (!empty)
            {
                for (; p != b; p = p->bk)
                {
                    size_t size = chunksize(p);
                    mchunk* q;
                    /* each chunk claims to be free */
                    do_check_free_chunk(p);
                    /* chunk belongs in bin */
                    assert(small_index(size) == i);
                    assert(p->bk == b || chunksize(p->bk) == chunksize(p));
                    // chunk is followed by an inuse chunk
                    q = next_chunk(p);
                    if (q->head != FENCEPOST_HEAD)
                        do_check_inuse_chunk(q);
                }
            }
        }

        // Find x in a bin. Used in other check functions.
        bool bin_find(mchunk* x)
        {
            size_t size = chunksize(x);
            if (is_small(size))
            {
                uint sidx = small_index(size);
                mchunk* b = smallbin_at(sidx);
                if (smallmap_is_marked(sidx))
                {
                    mchunk* p = b;
                    do
                    {
                        if (p == x)
                            return true;
                    } while ((p = p->fd) != b);
                }
            }
            else
            {
                uint tidx = compute_tree_index(size);
                if (treemap_is_marked(tidx))
                {
                    tchunk* t = *treebin_at(tidx);
                    size_t sizebits = size << leftshift_for_tree_index(tidx);
                    while (t != null && chunksize(t) != size)
                    {
                        t = ((sizebits >> (int)(SIZE_T_BITSIZE - SIZE_T_ONE)) & 1) == 0 ? t->child0 : t->child1;
                        sizebits <<= 1;
                    }
                    if (t != null)
                    {
                        tchunk* u = t;
                        do
                        {
                            if (u == (tchunk*)x)
                                return true;
                        } while ((u = u->fd) != t);
                    }
                }
            }
            return false;
        }

        public class HeapStats
        {
            public long HeapSize;
            public long UsedChunks;
            public long UsedBytes;
            public long FreeChunks;
            public long FreeBytes;

            public override string ToString()
            {
                return "HeapSize=" + HeapSize + ", UB=" + UsedBytes + ", FB=" + FreeBytes
                    + ", UC=" + UsedChunks + ", FC=" + FreeChunks;
            }
        }

        // Check all properties of malloc_state.
        public HeapStats CheckHeap()
        {
            assert(is_initialized());

            // check bins
            for (uint i = 0; i < NSMALLBINS; ++i)
                do_check_smallbin(i);
            for (uint i = 0; i < NTREEBINS; ++i)
                do_check_treebin(i);

            if (dvsize != 0)
            {
                // check dv chunk
                do_check_any_chunk(dv);
                assert(dvsize == chunksize(dv));
                assert(dvsize >= MIN_CHUNK_SIZE);
                assert(!bin_find(dv));
            }

            if (top != null)
            {
                // check top chunk
                do_check_top_chunk(top);
                assert(topsize > 0);
                assert(!bin_find(top));
            }

            int usedChunks = 0;
            int freeChunks = 0;
            long freeBytes = 0;
            long usedBytes = 0;
            long heapSize = 0;
            heapSize += (long)(topsize + TOP_FOOT_SIZE);

            // Walk segments
            msegment* s = seg;
            while (s != null)
            {
                mchunk* q = align_as_chunk(s->baseAddr);
                mchunk* lastq = null;
                assert(pinuse(q));

                // Walk chunks
                while (segment_holds(s, q) 
                        && q != top && q->head != FENCEPOST_HEAD)
                {
                    var chunkSize = (long)chunksize(q);
                    heapSize += chunkSize;
                    if (is_inuse(q))
                    {
                        usedBytes += chunkSize;
                        usedChunks += 1;
                        assert(!bin_find(q));
                        do_check_inuse_chunk(q);
                    }
                    else
                    {
                        freeBytes += chunkSize;
                        freeChunks += 1;
                        assert(q == dv || bin_find(q));
                        assert(lastq == null || is_inuse(lastq)); /* Not 2 consecutive free */
                        do_check_free_chunk(q);
                    }
                    lastq = q;
                    q = next_chunk(q);
                }
                s = s->next;
            }


            assert(heapSize <= (long)footprint);
            assert(footprint <= max_footprint);

            var stats = new HeapStats();
            stats.HeapSize = heapSize;
            stats.FreeChunks = freeChunks;
            stats.FreeBytes = freeBytes;
            stats.UsedChunks = usedChunks;
            stats.UsedBytes = usedBytes;
            return stats;
        }


        // ----------------------- Operations on smallbins -----------------------

        //  Various forms of linking and unlinking are defined as macros.  Even
        //  the ones for trees, which are very long but have very short typical
        //  paths.  This is ugly but reduces reliance on inlining support of
        //  compilers.

        // Link a free chunk into a smallbin 
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        void insert_small_chunk(mchunk* p, size_t s)
        {
            uint I = small_index(s);
            mchunk* B = smallbin_at(I);
            mchunk* F = B;
            assert(s >= MIN_CHUNK_SIZE);
            if (!smallmap_is_marked(I))
                mark_smallmap(I);
            else if (RTCHECK(ok_address(B->fd)))
                F = B->fd;
            else
            {
                CallCorruptionErrorAction();
            }
            B->fd = p;
            F->bk = p;
            p->fd = F;
            p->bk = B;
        }

        // Unlink a chunk from a smallbin
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        void unlink_small_chunk(mchunk* p, size_t s)
        {
            mchunk* F = p->fd;
            mchunk* B = p->bk;
            uint I = small_index(s);
            assert(p != B);
            assert(p != F);
            assert(chunksize(p) == small_index2size(I));
            if (RTCHECK(F == smallbin_at(I) || (ok_address(F) && F->bk == p)))
            {
                if (B == F)
                {
                    clear_smallmap(I);
                }
                else if (RTCHECK(B == smallbin_at(I) ||
                                 (ok_address(B) && B->fd == p)))
                {
                    F->bk = B;
                    B->fd = F;
                }
                else
                {
                    CallCorruptionErrorAction();
                }
            }
            else
            {
                CallCorruptionErrorAction();
            }
        }

        ///* Unlink the first chunk from a smallbin */
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        void unlink_first_small_chunk(mchunk* b, mchunk* p, uint i)
        {
            mchunk* F = p->fd;
            assert(p != b);
            assert(p != F);
            assert(chunksize(p) == small_index2size(i));
            if (b == F)
            {
                clear_smallmap(i);
            }
            else if (RTCHECK(ok_address(F) && F->bk == p))
            {
                F->bk = b;
                b->fd = F;
            }
            else
            {
                CallCorruptionErrorAction();
            }
        }

        // Replace dv node, binning the old one
        // Used only when dvsize known to be small
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        void replace_dv(mchunk* p, size_t s)
        {
            size_t DVS = dvsize;
            assert(is_small(DVS));
            if (DVS != 0)
            {
                mchunk* DV = dv;
                insert_small_chunk(DV, DVS);
            }
            dvsize = s;
            dv = p;
        }

        // ------------------------- Operations on trees -------------------------

        // Insert chunk into tree
        void insert_large_chunk(tchunk* x, size_t s)
        {
            tchunk** H;
            uint I = compute_tree_index(s);
            H = treebin_at(I);
            x->index = I;
            x->child0 = x->child1 = null;
            if (!treemap_is_marked(I))
            {
                mark_treemap(I);
                *H = x;
                x->parent = (tchunk*)H;
                x->fd = x->bk = x;
            }
            else
            {
                tchunk* T = *H;
                size_t K = s << leftshift_for_tree_index(I);
                for (; ; )
                {
                    if (chunksize(T) != s)
                    {
                        tchunk** C = ((K >> (int)(SIZE_T_BITSIZE - SIZE_T_ONE)) & 1) == 0 ? &T->child0 : &T->child1;
                        K <<= 1;
                        if (*C != null)
                            T = *C;
                        else if (RTCHECK(ok_address(C)))
                        {
                            *C = x;
                            x->parent = T;
                            x->fd = x->bk = x;
                            break;
                        }
                        else
                        {
                            CallCorruptionErrorAction();
                            break;
                        }
                    }
                    else
                    {
                        tchunk* F = T->fd;
                        if (RTCHECK(ok_address(T) && ok_address(F)))
                        {
                            T->fd = F->bk = x;
                            x->fd = F;
                            x->bk = T;
                            x->parent = null;
                            break;
                        }
                        else
                        {
                            CallCorruptionErrorAction();
                            break;
                        }
                    }
                }
            }
        }

        //  Unlink steps:
        //
        //  1. If x is a chained node, unlink it from its same-sized fd/bk links
        //     and choose its bk node as its replacement.
        //  2. If x was the last node of its size, but not a leaf node, it must
        //     be replaced with a leaf node (not merely one with an open left or
        //     right), to make sure that lefts and rights of descendents
        //     correspond properly to bit masks.  We use the rightmost descendent
        //     of x.  We could use any other leaf, but this is easy to locate and
        //     tends to counteract removal of leftmosts elsewhere, and so keeps
        //     paths shorter than minimally guaranteed.  This doesn't loop much
        //     because on average a node in a tree is near the bottom.
        //  3. If x is the base of a chain (i.e., has parent links) relink
        //     x's parent and children to x's replacement (or null if none).

        void unlink_large_chunk(tchunk* x)
        {
            tchunk* XP = x->parent;
            tchunk* R;
            if (x->bk != x)
            {
                tchunk* F = x->fd;
                R = x->bk;
                if (RTCHECK(ok_address(F) && F->bk == x && R->fd == x))
                {
                    F->bk = R;
                    R->fd = F;
                }
                else
                {
                    CallCorruptionErrorAction();
                }
            }
            else
            {
                tchunk** RP;
                if (((R = *(RP = &(x->child1))) != null) ||
                    ((R = *(RP = &(x->child0))) != null))
                {
                    tchunk** CP;
                    while ((*(CP = &(R->child1)) != null) ||
                           (*(CP = &(R->child0)) != null))
                    {
                        R = *(RP = CP);
                    }
                    if (RTCHECK(ok_address(RP)))
                        *RP = null;
                    else
                    {
                        CallCorruptionErrorAction();
                    }
                }
            }
            if (XP != null)
            {
                tchunk** H = treebin_at(x->index);
                if (x == *H)
                {
                    if ((*H = R) == null)
                        clear_treemap(x->index);
                }
                else if (RTCHECK(ok_address(XP)))
                {
                    if (XP->child0 == x)
                        XP->child0 = R;
                    else
                        XP->child1 = R;
                }
                else
                    CallCorruptionErrorAction();
                if (R != null)
                {
                    if (RTCHECK(ok_address(R)))
                    {
                        tchunk* C0, C1;
                        R->parent = XP;
                        if ((C0 = x->child0) != null)
                        {
                            if (RTCHECK(ok_address(C0)))
                            {
                                R->child0 = C0;
                                C0->parent = R;
                            }
                            else
                                CallCorruptionErrorAction();
                        }
                        if ((C1 = x->child1) != null)
                        {
                            if (RTCHECK(ok_address(C1)))
                            {
                                R->child1 = C1;
                                C1->parent = R;
                            }
                            else
                                CallCorruptionErrorAction();
                        }
                    }
                    else
                        CallCorruptionErrorAction();
                }
            }
        }

        // Relays to large vs small bin operations 

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        void insert_chunk(mchunk* p, size_t s)
        {
            if (is_small(s))
                insert_small_chunk(p, s);
            else
                insert_large_chunk((tchunk*)p, s);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        void unlink_chunk(mchunk* p, size_t s)
        {
            if (is_small(s))
                unlink_small_chunk(p, s);
            else
                unlink_large_chunk((tchunk*)p);
        }

        // -------------------------- mspace management --------------------------

        // Initialize top chunk and its size 
        void init_top(mchunk* p, size_t psize)
        {
            // Ensure alignment
            size_t offset = align_offset(chunk2mem(p));
            p = (mchunk*)((byte*)p + offset);
            psize -= offset;

            top = p;
            topsize = psize;
            p->head = psize | PINUSE_BIT;
            // set size of fake trailing chunk holding overhead space only once
            chunk_plus_offset(p, psize)->head = TOP_FOOT_SIZE;
            trim_check = mparams.trim_threshold; // reset on each update
        }

        // Initialize bins for a new mstate that is otherwise zeroed out
        void init_bins()
        {
            /* Establish circular links for smallbins */
            uint i;
            for (i = 0; i < NSMALLBINS; ++i)
            {
                mchunk* bin = smallbin_at(i);
                bin->fd = bin->bk = bin;
            }
        }

        /// <summary>
        /// Default corruption action - forget all allocated memory.
        /// </summary>
        protected void ResetOnError()
        {
            int i;
            ++malloc_corruption_error_count;
            // Reinitialize fields to forget about all memory
            smallmap = treemap = 0;
            dvsize = topsize = 0;
            seg->baseAddr = null;
            seg->size = 0;
            seg->next = null;
            top = dv = null;
            for (i = 0; i < (int)NTREEBINS; ++i)
                *treebin_at((uint)i) = null;
            init_bins();
        }

        // Allocate chunk and prepend remainder with chunk in successor base.
        void* prepend_alloc(byte* newbase, byte* oldbase,
                                   size_t nb)
        {
            mchunk* p = align_as_chunk(newbase);
            mchunk* oldfirst = align_as_chunk(oldbase);
            size_t psize = (size_t)((byte*)oldfirst - (byte*)p);
            mchunk* q = chunk_plus_offset(p, nb);
            size_t qsize = psize - nb;
            set_size_and_pinuse_of_inuse_chunk(p, nb);

            assert((byte*)oldfirst > (byte*)q);
            assert(pinuse(oldfirst));
            assert(qsize >= MIN_CHUNK_SIZE);

            // consolidate remainder with first chunk of old base
            if (oldfirst == top)
            {
                size_t tsize = topsize += qsize;
                top = q;
                q->head = tsize | PINUSE_BIT;
                check_top_chunk(q);
            }
            else if (oldfirst == dv)
            {
                size_t dsize = dvsize += qsize;
                dv = q;
                set_size_and_pinuse_of_free_chunk(q, dsize);
            }
            else
            {
                if (!is_inuse(oldfirst))
                {
                    size_t nsize = chunksize(oldfirst);
                    unlink_chunk(oldfirst, nsize);
                    oldfirst = chunk_plus_offset(oldfirst, nsize);
                    qsize += nsize;
                }
                set_free_with_pinuse(q, qsize, oldfirst);
                insert_chunk(q, qsize);
                check_free_chunk(q);
            }

            check_malloced_chunk(chunk2mem(p), nb);
            return chunk2mem(p);
        }

        // Add a segment to hold a new noncontiguous region
        void add_segment(byte* tbase, size_t tsize, flag_t mmapped)
        {
            // Determine locations and sizes of segment, fenceposts, old top
            byte* old_top = (byte*)top;
            msegment* oldsp = segment_holding(old_top);
            byte* old_end = oldsp->baseAddr + oldsp->size;
            size_t ssize = pad_request((size_t)sizeof(msegment));
            byte* rawsp = old_end - (ssize + FOUR_SIZE_T_SIZES + CHUNK_ALIGN_MASK);
            size_t offset = align_offset(chunk2mem(rawsp));
            byte* asp = rawsp + offset;
            byte* csp = (asp < (old_top + MIN_CHUNK_SIZE)) ? old_top : asp;
            mchunk* sp = (mchunk*)csp;
            msegment* ss = (msegment*)(chunk2mem(sp));
            mchunk* tnext = chunk_plus_offset(sp, ssize);
            mchunk* p = tnext;
            int nfences = 0;

            // reset top to new space
            init_top((mchunk*)tbase, tsize - TOP_FOOT_SIZE);

            // Set up segment record
            assert(is_aligned(ss));
            set_size_and_pinuse_of_inuse_chunk(sp, ssize);
            *ss = *seg; // Push current record
            seg->baseAddr = tbase;
            seg->size = tsize;
            seg->sflags = mmapped;
            seg->next = ss;

            // Insert trailing fenceposts
            for (; ; )
            {
                mchunk* nextp = chunk_plus_offset(p, SIZE_T_SIZE);
                p->head = FENCEPOST_HEAD;
                ++nfences;
                if ((byte*)(&(nextp->head_ptr)) < old_end)
                    p = nextp;
                else
                    break;
            }
            assert(nfences >= 2);

            // Insert the rest of old top into a bin as an ordinary free chunk
            if (csp != old_top)
            {
                mchunk* q = (mchunk*)old_top;
                size_t psize = (size_t)(csp - old_top);
                mchunk* tn = chunk_plus_offset(q, psize);
                set_free_with_pinuse(q, psize, tn);
                insert_chunk(q, psize);
            }

            check_top_chunk(top);
        }

        // -------------------------- System allocation --------------------------

        // Get memory from system using MMAP
        void* sys_alloc(size_t nb)
        {
            byte* tbase = null;
            size_t tsize = 0;
            flag_t mmap_flag = 0;
            size_t asize; // allocation size

            ensure_initialization();

            asize = granularity_align(nb + SYS_ALLOC_PADDING);
            if (asize <= nb)
                return null; // wraparound

            // Try getting memory via CallMoreCore
            // In all cases, we need to request enough bytes from system to ensure
            // we can malloc nb bytes upon success, so pad with enough space for
            // top_foot, plus alignment-pad to make sure we don't lose bytes if
            // not on boundary, and round this up to a granularity unit.

            if (tbase == null)
            {
                // Try MMAP
                byte* mp = (byte*)CallMoreCore(ref asize);
                if (mp != null)
                {
                    tbase = mp;
                    tsize = asize;
                    mmap_flag = flag_t.USE_MMAP_BIT;
                }
            }

            if (tbase != null)
            {
                if ((footprint += tsize) > max_footprint)
                    max_footprint = footprint;

                if (!is_initialized())
                {
                    throw new DlMallocException("Must already be initialized");
                }

                // Try to merge with an existing segment
                // Only consider most recent segment if traversal suppressed 
                msegment* sp = seg;
                while (sp != null && tbase != sp->baseAddr + sp->size)
                    sp = NO_SEGMENT_TRAVERSAL ? null : sp->next;

                if (sp != null &&
                    !is_extern_segment(sp) &&
                    (sp->sflags & flag_t.USE_MMAP_BIT) == mmap_flag &&
                    segment_holds(sp, top))
                {
                    // append
                    sp->size += tsize;
                    init_top(top, topsize + tsize);
                }
                else
                {
                    if (tbase < least_addr)
                        least_addr = tbase;
                    sp = seg;
                    while (sp != null && sp->baseAddr != tbase + tsize)
                        sp = (NO_SEGMENT_TRAVERSAL) ? null : sp->next;
                    if (sp != null &&
                        !is_extern_segment(sp) &&
                        (sp->sflags & flag_t.USE_MMAP_BIT) == mmap_flag)
                    {
                        byte* oldbase = sp->baseAddr;
                        sp->baseAddr = tbase;
                        sp->size += tsize;
                        return prepend_alloc(tbase, oldbase, nb);
                    }
                    else
                        add_segment(tbase, tsize, mmap_flag);
                }

                if (nb < topsize)
                {
                    // Allocate from new or extended top space
                    size_t rsize = topsize -= nb;
                    mchunk* p = top;
                    mchunk* r = top = chunk_plus_offset(p, nb);
                    r->head = rsize | PINUSE_BIT;
                    set_size_and_pinuse_of_inuse_chunk(p, nb);
                    check_top_chunk(top);
                    check_malloced_chunk(chunk2mem(p), nb);
                    return chunk2mem(p);
                }
            }

            CallMallocFailureAction();
            return null;
        }


        // -----------------------  system deallocation -------------------------- 

        // Unmap and unlink any mmapped segments that don't contain used chunks
        size_t release_unused_segments()
        {
            size_t released = 0;
            int nsegs = 0;
            msegment* pred = seg;
            msegment* sp = pred->next;
            while (sp != null)
            {
                byte* baseAddr = sp->baseAddr;
                size_t size = sp->size;
                msegment* next = sp->next;
                ++nsegs;
                if (is_mmapped_segment(sp) && !is_extern_segment(sp))
                {
                    mchunk* p = align_as_chunk(baseAddr);
                    size_t psize = chunksize(p);
                    // Can unmap if first chunk holds entire segment and not pinned
                    if (!is_inuse(p) && (byte*)p + psize >= baseAddr + size - TOP_FOOT_SIZE)
                    {
                        tchunk* tp = (tchunk*)p;
                        assert(segment_holds(sp, (byte*)sp));
                        if (p == dv)
                        {
                            dv = null;
                            dvsize = 0;
                        }
                        else
                        {
                            unlink_large_chunk(tp);
                        }
                        if (CallReleaseCore(baseAddr, size))
                        {
                            released += size;
                            footprint -= size;
                            // unlink obsoleted record
                            sp = pred;
                            sp->next = next;
                        }
                        else
                        { // back out if cannot unmap
                            insert_large_chunk(tp, psize);
                        }
                    }
                }
                if (NO_SEGMENT_TRAVERSAL) // scan only first segment
                    break;
                pred = sp;
                sp = next;
            }
            // Reset check counter
            release_checks = (((size_t)nsegs > (size_t)MAX_RELEASE_CHECK_RATE) ?
                                 (size_t)nsegs : (size_t)MAX_RELEASE_CHECK_RATE);
            return released;
        }

        int sys_trim(size_t pad)
        {
            size_t released = 0;
            ensure_initialization();
            if (pad < MAX_REQUEST && is_initialized())
            {
                pad += TOP_FOOT_SIZE; // ensure enough room for segment overhead

                if (topsize > pad)
                {
                    // Shrink top space in granularity-size units, keeping at least one
                    size_t unit = mparams.granularity;
                    size_t extra = ((topsize - pad + (unit - SIZE_T_ONE)) / unit -
                                    SIZE_T_ONE) * unit;
                    msegment* sp = segment_holding((byte*)top);

                    if (!is_extern_segment(sp))
                    {
                        if (is_mmapped_segment(sp))
                        {
                            if (sp->size >= extra &&
                                !has_segment_link(sp))
                            {
                                // can't shrink if pinned
                                size_t newsize = sp->size - extra;

                                if (CallReleaseCore(sp->baseAddr + newsize, extra))
                                {
                                    released = extra;
                                }
                            }
                        }
                    }

                    if (released != 0)
                    {
                        sp->size -= released;
                        footprint -= released;
                        init_top(top, topsize - released);
                        check_top_chunk(top);
                    }
                }

                // Unmap any unused mmapped segments
                released += release_unused_segments();

                // On failure, disable autotrim to avoid repeated failed future calls
                if (released == 0 && topsize > trim_check)
                    trim_check = MAX_SIZE_T;
            }

            return (released != 0) ? 1 : 0;
        }

        // Consolidate and bin a chunk. Differs from exported versions
        //   of free mainly in that the chunk need not be marked as inuse.
        void dispose_chunk(mchunk* p, size_t psize)
        {
            mchunk* next = chunk_plus_offset(p, psize);
            if (!pinuse(p))
            {
                mchunk* prev;
                size_t prevsize = p->prev_foot;
                prev = chunk_minus_offset(p, prevsize);
                psize += prevsize;
                p = prev;
                if (RTCHECK(ok_address(prev)))
                {
                    // consolidate backward
                    if (p != dv)
                    {
                        unlink_chunk(p, prevsize);
                    }
                    else if ((next->head & INUSE_BITS) == INUSE_BITS)
                    {
                        dvsize = psize;
                        set_free_with_pinuse(p, psize, next);
                        return;
                    }
                }
                else
                {
                    CallCorruptionErrorAction();
                    return;
                }
            }
            if (RTCHECK(ok_address(next)))
            {
                if (!cinuse(next))
                {
                    // consolidate forward
                    if (next == top)
                    {
                        size_t tsize = topsize += psize;
                        top = p;
                        p->head = tsize | PINUSE_BIT;
                        if (p == dv)
                        {
                            dv = null;
                            dvsize = 0;
                        }
                        return;
                    }
                    else if (next == dv)
                    {
                        size_t dsize = dvsize += psize;
                        dv = p;
                        set_size_and_pinuse_of_free_chunk(p, dsize);
                        return;
                    }
                    else
                    {
                        size_t nsize = chunksize(next);
                        psize += nsize;
                        unlink_chunk(next, nsize);
                        set_size_and_pinuse_of_free_chunk(p, psize);
                        if (p == dv)
                        {
                            dvsize = psize;
                            return;
                        }
                    }
                }
                else
                {
                    set_free_with_pinuse(p, psize, next);
                }
                insert_chunk(p, psize);
            }
            else
            {
                CallCorruptionErrorAction();
            }
        }

        // ---------------------------- malloc ---------------------------

        // allocate a large request from the best fitting chunk in a treebin
        void* tmalloc_large(size_t nb)
        {
            tchunk* v = null;
            size_t rsize = (size_t)(-(long)nb); // Unsigned negation
            tchunk* t;
            uint idx = compute_tree_index(nb);
            if ((t = *treebin_at(idx)) != null)
            {
                /* Traverse tree for this bin looking for node with size == nb */
                size_t sizebits = nb << leftshift_for_tree_index(idx);
                tchunk* rst = null;  // The deepest untaken right subtree
                for (; ; )
                {
                    tchunk* rt;
                    size_t trem = chunksize(t) - nb;
                    if (trem < rsize)
                    {
                        v = t;
                        if ((rsize = trem) == 0)
                            break;
                    }
                    rt = t->child1;
                    t = ((sizebits >> (int)(SIZE_T_BITSIZE - SIZE_T_ONE)) & 1) == 0 ? t->child0 : t->child1;
                    if (rt != null && rt != t)
                        rst = rt;
                    if (t == null)
                    {
                        t = rst; // set t to least subtree holding sizes > nb
                        break;
                    }
                    sizebits <<= 1;
                }
            }
            if (t == null && v == null)
            {
                // set t to root of next non-empty treebin
                uint leftbits = left_bits(idx2bit(idx)) & treemap;
                if (leftbits != 0)
                {
                    uint leastbit = least_bit(leftbits);
                    uint i = compute_bit2idx(leastbit);
                    t = *treebin_at(i);
                }
            }

            while (t != null)
            {
                // find smallest of tree or subtree
                size_t trem = chunksize(t) - nb;
                if (trem < rsize)
                {
                    rsize = trem;
                    v = t;
                }
                t = leftmost_child(t);
            }

            // If dv is a better fit, return 0 so malloc will use it
            if (v != null && rsize < (size_t)(dvsize - nb))
            {
                if (RTCHECK(ok_address(v)))
                {
                    // split
                    mchunk* r = chunk_plus_offset(v, nb);
                    assert(chunksize(v) == rsize + nb);
                    if (RTCHECK(ok_next(v, r)))
                    {
                        unlink_large_chunk(v);
                        if (rsize < MIN_CHUNK_SIZE)
                            set_inuse_and_pinuse(v, (rsize + nb));
                        else
                        {
                            set_size_and_pinuse_of_inuse_chunk((mchunk*)v, nb);
                            set_size_and_pinuse_of_free_chunk(r, rsize);
                            insert_chunk(r, rsize);
                        }
                        return chunk2mem(v);
                    }
                }
                CallCorruptionErrorAction();
            }
            return null;
        }

        // allocate a small request from the best fitting chunk in a treebin
        void* tmalloc_small(size_t nb)
        {
            tchunk* t;
            tchunk* v;
            size_t rsize;
            uint leastbit = least_bit(treemap);
            uint i = compute_bit2idx(leastbit);
            v = t = *treebin_at(i);
            rsize = chunksize(t) - nb;

            while ((t = leftmost_child(t)) != null)
            {
                size_t trem = chunksize(t) - nb;
                if (trem < rsize)
                {
                    rsize = trem;
                    v = t;
                }
            }

            if (RTCHECK(ok_address(v)))
            {
                mchunk* r = chunk_plus_offset(v, nb);
                assert(chunksize(v) == rsize + nb);
                if (RTCHECK(ok_next(v, r)))
                {
                    unlink_large_chunk(v);
                    if (rsize < MIN_CHUNK_SIZE)
                        set_inuse_and_pinuse(v, (rsize + nb));
                    else
                    {
                        set_size_and_pinuse_of_inuse_chunk((mchunk*)v, nb);
                        set_size_and_pinuse_of_free_chunk(r, rsize);
                        replace_dv(r, rsize);
                    }
                    return chunk2mem(v);
                }
            }

            CallCorruptionErrorAction();
            return null;
        }

        // Traversal
        void internal_inspect_all(DlInspect handler)
        {
            if (!is_initialized())
                return;

            mchunk* top2 = top;
            msegment* s;
            for (s = seg; s != null; s = s->next)
            {
                mchunk* q = align_as_chunk(s->baseAddr);
                while (segment_holds(s, q) && q->head != FENCEPOST_HEAD)
                {
                    mchunk* next = next_chunk(q);
                    size_t sz = chunksize(q);
                    size_t used;
                    void* start;
                    if (is_inuse(q))
                    {
                        used = sz - CHUNK_OVERHEAD; // must not be mmapped
                        start = chunk2mem(q);
                    }
                    else
                    {
                        used = 0;
                        if (is_small(sz))
                        {     /* offset by possible bookkeeping */
                            start = (void*)((byte*)q + sizeof(mchunk));
                        }
                        else
                        {
                            start = (void*)((byte*)q + sizeof(tchunk));
                        }
                    }
                    if (start < (void*)next)  // skip if all space is bookkeeping
                        handler(start, next, used);
                    if (q == top2)
                        break;
                    q = next;
                }
            }
        }

        // ------------------ Exported realloc, memalign, etc --------------------



        // ----------------------------- user mspaces ----------------------------


        protected static void MemClear(void* mem, long size)
        {
            var b = (byte*)mem;
            while (--size >= 0)
                *b++ = 0;
        }

        void init_user_mstate(byte* tbase, size_t tsize)
        {
            mchunk* mn;
            mchunk* msp = align_as_chunk(tbase);
            void* m = chunk2mem(msp);

            smallbins = (mchunk**)Marshal.AllocHGlobal(sizeof(mchunk*) * ((int)((NSMALLBINS + 1) * 2)));
            treebins = (tchunk**)Marshal.AllocHGlobal(sizeof(tchunk*) * ((int)NTREEBINS));
            seg = (msegment*)Marshal.AllocHGlobal(sizeof(msegment));
            MemClear(smallbins, sizeof(mchunk*) * ((int)((NSMALLBINS + 1) * 2)));
            MemClear(treebins, sizeof(tchunk*) * ((int)NTREEBINS));
            MemClear(seg, sizeof(msegment));

            size_t msize = 0;
            msp->head = (msize | INUSE_BITS);
            seg->baseAddr = least_addr = tbase;
            seg->size = footprint = max_footprint = tsize;
            magic = mparams.magic;
            release_checks = MAX_RELEASE_CHECK_RATE;
            mflags = mparams.default_mflags;

            init_bins();
            mn = next_chunk(mem2chunk(m));
            init_top(mn, (size_t)((tbase + tsize) - (byte*)mn) - TOP_FOOT_SIZE);
            check_top_chunk(top);
        }

        // Initialize the malloc space with the
        // given initial capacity, or, if 0, the default granularity size. It
        // throws an exception if there is no system memory available to create the
        // space. The capacity of the space will grow
        // dynamically as needed to service malloc requests. You can
        // control the sizes of incremental increases of this space by
        // compiling with a different DEFAULT_GRANULARITY.
        // Calling this function is optional.
        public void Init(size_t capacity)
        {
            ensure_initialization();
            size_t rs = capacity == 0 ? mparams.granularity : capacity + TOP_FOOT_SIZE;
            size_t tsize = granularity_align(rs);
            byte* tbase = (byte*)CallMoreCore(ref tsize);
            if (tbase != null)
            {
                init_user_mstate(tbase, tsize);
                seg->sflags = flag_t.USE_MMAP_BIT;
            }
            else
            {
                throw new DlMallocException("Out of memory, cannot initialize malloc.");
            }
        }

        //  destroy_mspace destroys the given space, and attempts to return all
        //  of its memory back to the system, returning the total number of
        //  bytes freed. After destruction, the results of access to all memory
        //  used by the space become undefined.
        public void Dispose()
        {
            msegment* sp = seg;
            while (sp != null)
            {
                byte* baseAddr = sp->baseAddr;
                size_t size = sp->size;
                flag_t flag = sp->sflags;
                sp = sp->next;
                if ((flag & flag_t.USE_MMAP_BIT) != 0 && (flag & flag_t.EXTERN_BIT) == 0 &&
                    CallReleaseCore(baseAddr, size))
                {
                    //freed += size;
                }
            }
            Marshal.FreeHGlobal((IntPtr)smallbins);
            Marshal.FreeHGlobal((IntPtr)treebins);
            Marshal.FreeHGlobal((IntPtr)seg);
            smallbins = null;
            treebins = null;
            seg = null;
            top = null;
            CallDisposeFinal();
        }

        /// <summary>
        /// Malloc can be exposed or used by the inheriting class
        /// </summary>
        protected void* Malloc(size_t length)
        {
            //     Basic algorithm:
            //     If a small request (< 256 bytes minus per-chunk overhead):
            //       1. If one exists, use a remainderless chunk in associated smallbin.
            //          (Remainderless means that there are too few excess bytes to
            //          represent as a chunk.)
            //       2. If it is big enough, use the dv chunk, which is normally the
            //          chunk adjacent to the one used for the most recent small request.
            //       3. If one exists, split the smallest available chunk in a bin,
            //          saving remainder in dv.
            //       4. If it is big enough, use the top chunk.
            //       5. If available, get memory from system and use it
            //     Otherwise, for a large request:
            //       1. Find the smallest available binned chunk that fits, and use it
            //          if it is better fitting than dv chunk, splitting if necessary.
            //       2. If better fitting than any binned chunk, use the dv chunk.
            //       3. If it is big enough, use the top chunk.
            //       4. If request size >= mmap threshold, try to directly mmap this chunk.
            //       5. If available, get memory from system and use it

            if (!is_initialized())
                Init(0);

            if (!ok_magic())
            {
                CallUsageErrorAction(null);
                return null;
            }
            void* mem;
            size_t nb;
            if (length <= MAX_SMALL_REQUEST)
            {
                uint idx;
                uint smallbits;
                nb = (length < MIN_REQUEST) ? MIN_CHUNK_SIZE : pad_request(length);
                idx = small_index(nb);
                smallbits = smallmap >> (int)idx;

                if ((smallbits & 0x3U) != 0)
                {
                    // Remainderless fit to a smallbin.
                    mchunk* b, p;
                    idx += ~smallbits & 1;       // Uses next bin if idx empty
                    b = smallbin_at(idx);
                    p = b->fd;
                    assert(chunksize(p) == small_index2size(idx));
                    unlink_first_small_chunk(b, p, idx);
                    set_inuse_and_pinuse(p, small_index2size(idx));
                    mem = chunk2mem(p);
                    check_malloced_chunk(mem, nb);
                    return mem;
                }
                else if (nb > dvsize)
                {
                    if (smallbits != 0)
                    {
                        // Use chunk in next nonempty smallbin
                        mchunk* b, p, r;
                        size_t rsize;
                        uint leftbits = (smallbits << (int)idx) & left_bits(idx2bit(idx));
                        uint leastbit = least_bit(leftbits);
                        uint i = compute_bit2idx(leastbit);
                        b = smallbin_at(i);
                        p = b->fd;
                        assert(chunksize(p) == small_index2size(i));
                        unlink_first_small_chunk(b, p, i);
                        rsize = small_index2size(i) - nb;
                        // Fit here cannot be remainderless if 4byte sizes
                        if (SIZE_T_SIZE != 4 && rsize < MIN_CHUNK_SIZE)
                            set_inuse_and_pinuse(p, small_index2size(i));
                        else
                        {
                            set_size_and_pinuse_of_inuse_chunk(p, nb);
                            r = chunk_plus_offset(p, nb);
                            set_size_and_pinuse_of_free_chunk(r, rsize);
                            replace_dv(r, rsize);
                        }
                        mem = chunk2mem(p);
                        check_malloced_chunk(mem, nb);
                        return mem;
                    }
                    else if (treemap != 0 && (mem = tmalloc_small(nb)) != null)
                    {
                        check_malloced_chunk(mem, nb);
                        return mem;
                    }
                }
            }
            else if (length >= MAX_REQUEST)
                nb = MAX_SIZE_T; // Too big to allocate. Force failure (in sys alloc)
            else
            {
                nb = pad_request(length);
                if (treemap != 0 && (mem = tmalloc_large(nb)) != null)
                {
                    check_malloced_chunk(mem, nb);
                    return mem;
                }
            }

            if (nb <= dvsize)
            {
                size_t rsize = dvsize - nb;
                mchunk* p = dv;
                if (rsize >= MIN_CHUNK_SIZE)
                {
                    // split dv
                    mchunk* r = dv = chunk_plus_offset(p, nb);
                    dvsize = rsize;
                    set_size_and_pinuse_of_free_chunk(r, rsize);
                    set_size_and_pinuse_of_inuse_chunk(p, nb);
                }
                else
                {
                    // exhaust dv
                    size_t dvs = dvsize;
                    dvsize = 0;
                    dv = null;
                    set_inuse_and_pinuse(p, dvs);
                }
                mem = chunk2mem(p);
                check_malloced_chunk(mem, nb);
                return mem;
            }
            else if (nb < topsize)
            {
                // Split top
                size_t rsize = topsize -= nb;
                mchunk* p = top;
                mchunk* r = top = chunk_plus_offset(p, nb);
                r->head = rsize | PINUSE_BIT;
                set_size_and_pinuse_of_inuse_chunk(p, nb);
                mem = chunk2mem(p);
                check_top_chunk(top);
                check_malloced_chunk(mem, nb);
                return mem;
            }

            mem = sys_alloc(nb);

            return mem;
        }

        /// <summary>
        /// Free can be exposed or used by the inheriting class
        /// </summary>
        protected void Free(void* mem)
        {
            // Consolidate freed chunks with preceeding or succeeding bordering
            // free chunks, if they exist, and then place in a bin.  Intermixed
            // with special cases for top, dv, mmapped chunks, and usage errors.

            if (mem == null)
                return;

            if (!is_initialized())
                Init(0);

            mchunk* p = mem2chunk(mem);
            if (!ok_magic())
            {
                CallUsageErrorAction(p);
                return;
            }
            check_inuse_chunk(p);
            if (!RTCHECK(ok_address(p) && ok_inuse(p)))
            {
                CallUsageErrorAction(p);
                return;
            }
            assert(!is_mmapped(p));


            size_t psize = chunksize(p);
            mchunk* next = chunk_plus_offset(p, psize);
            if (!pinuse(p))
            {
                size_t prevsize = p->prev_foot;
                mchunk* prev = chunk_minus_offset(p, prevsize);
                psize += prevsize;
                p = prev;
                if (RTCHECK(ok_address(prev)))
                {
                    // consolidate backward
                    if (p != dv)
                    {
                        unlink_chunk(p, prevsize);
                    }
                    else if ((next->head & INUSE_BITS) == INUSE_BITS)
                    {
                        dvsize = psize;
                        set_free_with_pinuse(p, psize, next);
                        return;
                    }
                }
                else
                {
                    CallUsageErrorAction(p);
                    return;
                }
            }

            if (RTCHECK(ok_next(p, next) && ok_pinuse(next)))
            {
                if (!cinuse(next))
                {
                    // consolidate forward
                    if (next == top)
                    {
                        size_t tsize = topsize += psize;
                        top = p;
                        p->head = tsize | PINUSE_BIT;
                        if (p == dv)
                        {
                            dv = null;
                            dvsize = 0;
                        }
                        if (should_trim(tsize))
                            sys_trim(0);
                        return;
                    }
                    else if (next == dv)
                    {
                        size_t dsize = dvsize += psize;
                        dv = p;
                        set_size_and_pinuse_of_free_chunk(p, dsize);
                        return;
                    }
                    else
                    {
                        size_t nsize = chunksize(next);
                        psize += nsize;
                        unlink_chunk(next, nsize);
                        set_size_and_pinuse_of_free_chunk(p, psize);
                        if (p == dv)
                        {
                            dvsize = psize;
                            return;
                        }
                    }
                }
                else
                    set_free_with_pinuse(p, psize, next);

                if (is_small(psize))
                {
                    insert_small_chunk(p, psize);
                    check_free_chunk(p);
                }
                else
                {
                    tchunk* tp = (tchunk*)p;
                    insert_large_chunk(tp, psize);
                    check_free_chunk(p);
                    if (--release_checks == 0)
                        release_unused_segments();
                }
                return;
            }
            CallUsageErrorAction(p);
        }

        public delegate void DlInspect(void* start, void* end, ulong usedBytes);

        protected void InspectAll(DlInspect handler)
        {
            if (ok_magic())
            {
                internal_inspect_all(handler);
            }
            else
            {
                CallUsageErrorAction(null);
            }
        }

        protected int Trim(size_t pad = 0)
        {
            int result = 0;
            if (ok_magic())
            {
                result = sys_trim(pad);
            }
            else
            {
                CallUsageErrorAction(null);
            }
            return result;
        }
    }
}
