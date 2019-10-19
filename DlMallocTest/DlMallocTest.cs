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

using System;
using System.Collections.Generic;
using System.Linq;
using Gosub.DlMalloc;

namespace Gosub.DlMallocTest
{
    public unsafe class DlMallocTest
    {
        Dictionary<long, int> mAllocatedMem = new Dictionary<long, int>();
        DlMallocTestMemory mMallocMem;


        Dictionary<long, ArraySegment<byte>> mAllocatedSegments = new Dictionary<long, ArraySegment<byte>>();
        DlMallocSegment mMallocSeg;
        ulong mAllocatedBytes;

        public class UnitTestFailException : Exception
        {
            public UnitTestFailException(string message) : base(message) { }
        }

        public void Test()
        {
            try
            {
                Console.WriteLine("Testing DlMalloc...");
                TestInternal();
                Console.WriteLine("Unit test passed!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unit test failed: " + ex.Message);
            }
        }

        public void TestInternal()
        {
            // Verify unit test detects corrupted memory
            ResetMalloc();
            TestUnitTest();

            // Test array segment allocateor
            Console.WriteLine("Testing array segment allocator");
            ResetMalloc();
            SegRigorousAllocAndFree();
            if (mAllocatedSegments.Count < 7000)
                throw new UnitTestFailException("Expecting at least 7000 memory allocations");
            if (mMallocSeg.SegmentCount == 0)
                throw new UnitTestFailException("Expecting some segments to be allocated");
            // NOTE: Malloc trimmed old small segments, so there's a lot fewer than 12
            if (mMallocSeg.SegmentCount > 12)
                throw new UnitTestFailException("Expecting fewer allocations with exponential growth");
            SegDeleteAll();
            if (mAllocatedBytes != 0 || mAllocatedSegments.Count != 0)
                throw new UnitTestFailException("All memory should be deallocated here");

            // Test normal exponential heap growth
            Console.WriteLine("Testing normal heap growth");
            ResetMalloc();
            MemRigorousAllocAndFree();
            if (mAllocatedMem.Count < 7000)
                throw new UnitTestFailException("Expecting at least 7000 memory allocations");
            var segmentsWithReleaseCore = mMallocMem.SegmentCount;
            if (segmentsWithReleaseCore == 0)
                throw new UnitTestFailException("Expecting some segments to be allocated");
            // NOTE: Malloc trimmed old small segments, so there's a lot fewer than 12
            if (segmentsWithReleaseCore > 12)
                throw new UnitTestFailException("Expecting fewer allocations with exponential growth");
            MemDeleteAll();
            if (mAllocatedBytes != 0 || mAllocatedMem.Count != 0)
                throw new UnitTestFailException("All memory should be deallocated here");

            // Test normal exponential heap growth with failure to ever free memory
            Console.WriteLine("Testing ForceFailReleaseCore=true");
            ResetMalloc();
            mMallocMem.ForceFailReleaseCore = true;
            MemRigorousAllocAndFree();
            if (mMallocMem.SegmentCount > 12)
                throw new UnitTestFailException("Expecting fewer allocations with exponential growth");
            if (mMallocMem.SegmentCount <= segmentsWithReleaseCore)
                throw new UnitTestFailException("Expecting malloc to have more segments with ForceFailReleaseCore");
            MemDeleteAll();
            if (mAllocatedBytes != 0)
                throw new UnitTestFailException("All memory should be deallocated here");

            // Test linear heap growth
            Console.WriteLine("Testing linear heap growth");
            ResetMalloc();
            mMallocMem.MaxGrowSize = 0; // Linear allocation in chunks of 65536
            MemRigorousAllocAndFree();
            var s1 = mMallocMem.SegmentCount;
            if (s1 < 300)
                throw new UnitTestFailException("Expecting more segments with linear growth");
            MemDeleteHalf();
            MemDeleteHalf();
            MemDeleteHalf();
            mMallocMem.Trim();
            if (mMallocMem.SegmentCount == s1)
                throw new UnitTestFailException("Expecting malloc to trim some segments");
            MemDeleteAll();
            if (mAllocatedBytes != 0)
                throw new UnitTestFailException("All memory should be deallocated here");
            mMallocMem.Trim();
            // TBD: Why doesn't malloc trim everything here?
            if (mMallocMem.SegmentCount > 4)
                throw new UnitTestFailException("Expecting malloc to trim most segments");

            // Test coelescence with linear growth
            Console.WriteLine("Testing coelescence with linear heap growth");
            ResetMalloc();
            mMallocMem.PreAllocate = true;
            mMallocMem.MaxGrowSize = 0;
            MemRigorousAllocAndFree();
            // TBD: Why are there two segments here?
            if (mMallocMem.SegmentCount > 4)
                throw new UnitTestFailException("Malloc should be coelescing pages");
        }

        void ResetMalloc()
        {
            if (mMallocMem != null)
                mMallocMem.Dispose();
            mMallocMem = new DlMallocTestMemory();
            mAllocatedMem.Clear();

            if (mMallocSeg != null)
                mMallocSeg.Dispose();
            mMallocSeg = new DlMallocSegment();
            mAllocatedSegments.Clear();
            mAllocatedBytes = 0;
        }

        private void TestUnitTest()
        {
            MemAllocBlocks(0, 4000, 1, false);
            var mem1 = (byte*)MemMalloc(20);
            mem1[0]++;
            var mem2 = (byte*)MemMalloc(20);
            mem2[19]++;
            MemAllocBlocks(0, 4000, 1, false);
            bool excepion = false;
            try { MemFree(mem1); } catch (UnitTestFailException) { excepion = true; }
            if (!excepion)
                throw new UnitTestFailException("Unit test failed to catch corrupted memory 2");
            excepion = false;
            try { MemFree(mem2); } catch (UnitTestFailException) { excepion = true; }
            if (!excepion)
                throw new UnitTestFailException("Unit test failed to catch corrupted memory 1");
        }

        // ----------------------------- MEM TEST ---------------------------

        /// <summary>
        /// Tons of pseudo random allocations and free's
        /// </summary>
        private void MemRigorousAllocAndFree()
        {
            MemAllocBlocks(0, 4000, 1);
            MemAllocBlocks(4000, 40000, 100);
            MemAllocBlocks(40000, 100000, 1000);
            MemDeleteAll();
            MemAllocBlocks(0, 4000, 1, false);
            MemAllocBlocks(40000, 100000, 1000, false);
            MemAllocBlocks(300000, 900000, 100000);
            MemAllocBlocks(0, 4000, 1, false);
            MemAllocBlocks(4000, 40000, 100, false);
            MemAllocBlocks(0, 4000, 1, false);
            MemDeleteHalf();
            MemAllocBlocks(0, 4000, 1, false);
            MemAllocBlocks(40000, 100000, 1000, false);
            MemAllocBlocks(0, 4000, 1, false);
            MemAllocBlocks(4000, 40000, 100, false);
        }

        /// <summary>
        /// Allocate sizes from min to max skipping step size. 
        /// Pseudo randomly deletes half the heap when deleteHalf is true
        /// </summary>
        private void MemAllocBlocks(int min, int max, int step, bool deleteHalf = true)
        {
            for (int size = min; size < max; size += step)
            {
                MemMalloc(size);
                if ((size % 2) != 0)
                    MemDeleteRandom(size + min + max + step);
            }
        }

        /// <summary>
        /// Pseudo randomly deletes 1/2 the heap
        /// </summary>
        private void MemDeleteHalf()
        {
            int count = mAllocatedMem.Count / 2;
            while (--count > 0)
                MemDeleteRandom(count);
        }

        /// <summary>
        /// Pseudo randomly delete an allocation
        /// </summary>
        private void MemDeleteRandom(int randomSeed)
        {
            // Delete a pseudo randomly generated allocation            
            var d = (randomSeed * 13 + (randomSeed >> 3) + (randomSeed >> 7)) % mAllocatedMem.Count;
            foreach (var kv in mAllocatedMem)
            {
                if (d-- == 0)
                {
                    MemFree((void*)kv.Key);
                    break;
                }
            }
        }

        /// <summary>
        /// Delete all allocations
        /// </summary>
        private void MemDeleteAll()
        {
            while (mAllocatedMem.Count != 0)
                MemFree((void*)mAllocatedMem.First().Key);
        }

        /// <summary>
        /// Allocates a block, fills with a pseudo random pattern
        /// </summary>
        void* MemMalloc(int length)
        {
            var address = mMallocMem.Malloc((uint)length);
            if (mAllocatedMem.ContainsKey((long)address))
                throw new UnitTestFailException("Unit test failed, allocation over the same area");
            mAllocatedMem[(long)address] = length;
            SetMem(address, length);
            mAllocatedBytes += (ulong)length;
            return address;
        }

        /// <summary>
        /// Verifies pseudo random pattern, then deallocates
        /// </summary>
        void MemFree(void* mem)
        {
            if (!mAllocatedMem.TryGetValue((long)mem, out var length))
                throw new UnitTestFailException("Unit test failed, memory wasn't allocated");
            mAllocatedMem.Remove((long)mem);
            if (!CheckMem(mem, length))
                throw new UnitTestFailException("Unit test failed, memory corrupted");
            ClearMem(mem, length);
            mMallocMem.Free(mem);
            mAllocatedBytes -= (ulong)length;
        }

        // ----------------------------- SEGMENT TEST -----------------------

        /// <summary>
        /// Tons of pseudo random allocations and free's
        /// </summary>
        private void SegRigorousAllocAndFree()
        {
            SegAllocBlocks(0, 4000, 1);
            SegAllocBlocks(4000, 40000, 100);
            SegAllocBlocks(40000, 100000, 1000);
            SegDeleteAll();
            SegAllocBlocks(0, 4000, 1, false);
            SegAllocBlocks(40000, 100000, 1000, false);
            SegAllocBlocks(300000, 900000, 100000);
            SegAllocBlocks(0, 4000, 1, false);
            SegAllocBlocks(4000, 40000, 100, false);
            SegAllocBlocks(0, 4000, 1, false);
            SegDeleteHalf();
            SegAllocBlocks(0, 4000, 1, false);
            SegAllocBlocks(40000, 100000, 1000, false);
            SegAllocBlocks(0, 4000, 1, false);
            SegAllocBlocks(4000, 40000, 100, false);
        }

        /// <summary>
        /// Allocate sizes from min to max skipping step size. 
        /// Pseudo randomly deletes half the heap when deleteHalf is true
        /// </summary>
        private void SegAllocBlocks(int min, int max, int step, bool deleteHalf = true)
        {
            for (int size = min; size < max; size += step)
            {
                SegMalloc(size);
                if ((size % 2) != 0)
                    SegDeleteRandom(size + min + max + step);
            }
        }

        /// <summary>
        /// Pseudo randomly deletes 1/2 the heap
        /// </summary>
        private void SegDeleteHalf()
        {
            int count = mAllocatedSegments.Count / 2;
            while (--count > 0)
                SegDeleteRandom(count);
        }

        /// <summary>
        /// Pseudo randomly delete an allocation
        /// </summary>
        private void SegDeleteRandom(int randomSeed)
        {
            // Delete a pseudo randomly generated allocation            
            var d = (randomSeed * 13 + (randomSeed >> 3) + (randomSeed >> 7)) % mAllocatedSegments.Count;
            foreach (var kv in mAllocatedSegments)
            {
                if (d-- == 0)
                {
                    SegFree(kv.Value);
                    break;
                }
            }
        }

        /// <summary>
        /// Delete all allocations
        /// </summary>
        private void SegDeleteAll()
        {
            while (mAllocatedSegments.Count != 0)
                SegFree(mAllocatedSegments.First().Value);
        }

        /// <summary>
        /// Allocates a block, fills with a pseudo random pattern
        /// </summary>
        ArraySegment<byte> SegMalloc(int length)
        {
            var seg = mMallocSeg.Malloc((uint)length);
            unsafe
            {
                fixed (byte* address = &seg.Array[seg.Offset])
                {
                    if (mAllocatedSegments.ContainsKey((long)address))
                        throw new UnitTestFailException("Unit test failed, allocation over the same area");
                    SetMem(address, length);
                    mAllocatedSegments[(long)address] = seg;
                }
            }
            if (seg.Count > 0
                && ((seg.Array[seg.Offset] & 0x80) == 0 || (seg.Array[seg.Offset + seg.Count - 1] & 0x80) == 0))
            {
                throw new UnitTestFailException("Unit test failed, expecting array segment to be set");
            }
            mAllocatedBytes += (ulong)length;
            return seg;
        }

        /// <summary>
        /// Verifies pseudo random pattern, then deallocates
        /// </summary>
        void SegFree(ArraySegment<byte> seg)
        {
            if (seg.Count > 0
                && ((seg.Array[seg.Offset] & 0x80) == 0 || (seg.Array[seg.Offset + seg.Count - 1] & 0x80) == 0))
            {
                throw new UnitTestFailException("Unit test failed, expecting array segment to be set");
            }

            unsafe
            {
                fixed (byte* address = &seg.Array[seg.Offset])
                {
                    if (!mAllocatedSegments.TryGetValue((long)address, out var length))
                        throw new UnitTestFailException("Unit test failed, segment wasn't allocated");
                    mAllocatedSegments.Remove((long)address);
                    if (!CheckMem(address, length.Count))
                        throw new UnitTestFailException("Unit test failed, segment corrupted");
                    ClearMem(address, length.Count);
                }
            }
            if (seg.Count > 0
                && (seg.Array[seg.Offset] != 0 || seg.Array[seg.Offset + seg.Count - 1] != 0))
            {
                throw new UnitTestFailException("Unit test failed, expecting array segment to be cleared");
            }
            mMallocSeg.Free(seg);
            mAllocatedBytes -= (ulong)seg.Count;
        }

        // ----------------------------- MISC MEM ---------------------------

        static void ClearMem(void* mem, int length)
        {
            var byteMem = (byte*)mem;

            while (length >= 4)
            {
                *(uint*)byteMem = 0;
                byteMem += 4;
                length -= 4;
            }

            while (--length >= 0)
            {
                *byteMem++ = 0;
            }
        }

        /// <summary>
        /// Fills memory with a pseudo random pattern
        /// </summary>
        private static void SetMem(void* mem, int length)
        {
            uint random = (uint)mem ^ 0x12345678;
            var byteMem = (byte*)mem;

            while (length >= 4)
            {
                *(uint*)byteMem = random | 0x80808080U;
                byteMem += 4;
                length -= 4;
                random += 0x01030507;
            }

            while (--length >= 0)
            {
                *byteMem++ = (byte)(random | 0x80);
                random = ((random + 1) << 8) | (random >> 24);
            }
        }

        /// <summary>
        /// Verifies the pseudo random pattern matches
        /// </summary>
        private static bool CheckMem(void* mem, int length)
        {
            uint random = (uint)mem ^ 0x12345678;
            var byteMem = (byte*)mem;

            while (length >= 4)
            {
                if (*(uint*)byteMem != (random | 0x80808080))
                    return false;
                byteMem += 4;
                length -= 4;
                random += 0x01030507;
            }

            while (--length >= 0)
            {
                if (*byteMem++ != (byte)(random | 0x80))
                    return false;
                random = ((random + 1) << 8) | (random >> 24);
            }
            return true;
        }

    }
}
