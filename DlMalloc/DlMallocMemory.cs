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
using System.Runtime.InteropServices;

namespace Gosub.DlMalloc
{
    public unsafe class DlMallocMemory : DlMallocBase
    {
        const ulong MIN_GRANULARITY = 65536;
        Dictionary<ulong, ulong> mAllocations = new Dictionary<ulong, ulong>();
        ulong mGrowSize;

        /// <summary>
        /// Clear the memory before releasing (set to false unless testing)
        /// </summary>
        protected bool ClearMemoryBeforeReleasing { get; set; }

        /// <summary>
        /// For each new allocation, the heap doubles in size until MaxGrowSize
        /// is reached which prevents numerous segments from accumulating.
        /// Set this to zero to force growth in 65536 byte increments.
        /// </summary>
        public ulong MaxGrowSize = 16 * 1024 * 1024;

        /// <summary>
        /// This was originally CALL_MMAP and is used to get more memory from
        /// the system. It's similar to CALL_MMAP, but can adjust the size to
        /// return more memory than requested (must be in units of page size).
        /// Returns null when out of memory or any kind of error.
        /// </summary>
        protected override void* CallMoreCore(ref ulong length)
        {
            mGrowSize = Math.Min(MaxGrowSize, Math.Max(mGrowSize, MIN_GRANULARITY / 2) * 2);
            length = Math.Max(length, mGrowSize);

            if (length > int.MaxValue)
                throw new DlMallocException("Request for too much memory, size=" + length);

            var p = Marshal.AllocHGlobal((int)length);
            if (p != null)
                mAllocations[(ulong)p] = length;
            return (void*)p;
        }

        /// <summary>
        /// This was originally CALL_MUNMAP and is used to release memory pages
        /// back to the OS.  This function works with pages, not with units
        /// individually allocated by CallMoreCore.  Therefore it could try to
        /// free part of an allocation or even multiple allocations at a time.
        /// Return true to indicate success, or false for failure (in which
        /// case the page is retained and used for future requests)
        /// </summary>
        protected override bool CallReleaseCore(void* address, ulong length)
        {
            if (mAllocations.TryGetValue((ulong)address, out var l) && l == length)
            {
                if (ClearMemoryBeforeReleasing)
                    MemClear(address, (long)length);
                Marshal.FreeHGlobal((IntPtr)address);
                mAllocations.Remove((ulong)address);
                return true;
            }
            return false;
        }

        protected override void CallDisposeFinal()
        {
            base.CallDisposeFinal();
            foreach (var kv in mAllocations)
                Marshal.FreeHGlobal((IntPtr)kv.Key);
            mAllocations.Clear();
        }

        new public void Free(void* mem)
        {
            base.Free(mem);
        }

        new public void* Malloc(ulong length)
        {
            return base.Malloc(length);
        }

    }
}
