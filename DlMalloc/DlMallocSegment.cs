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
    public class DlMallocSegment : DlMallocBase
    {
        const ulong MIN_GRANULARITY = 65536 * 2;

        struct AllocInfo
        {
            public byte[] Array;
            public ulong Length;
            public GCHandle Handle;
        }

        Dictionary<ulong, AllocInfo> mAllocations = new Dictionary<ulong, AllocInfo>();
        ulong mGrowSize;

        /// <summary>
        /// For each new allocation, the heap doubles in size until MaxGrowSize
        /// is reached which prevents numerous segments from accumulating.
        /// Set this to zero to force growth in 128K byte increments.
        /// </summary>
        public ulong MaxGrowSize = 16 * 1024 * 1024;


        /// <summary>
        /// This was originally CALL_MMAP and is used to get more memory from
        /// the system. It's similar to CALL_MMAP, but can adjust the size to
        /// return more memory than requested (must be in units of page size).
        /// Returns null when out of memory or any kind of error.
        /// </summary>
        unsafe protected override void* CallMoreCore(ref ulong size)
        {
            mGrowSize = Math.Min(MaxGrowSize, Math.Max(mGrowSize, MIN_GRANULARITY / 2) * 2);
            size = Math.Max(size, mGrowSize);

            if (size > int.MaxValue)
                throw new DlMallocException("Request for too much memory, size=" + size);

            var array = new byte[size];
            var handle = GCHandle.Alloc(array, GCHandleType.Pinned);
            var address = (void*)handle.AddrOfPinnedObject();
            mAllocations[(ulong)address] = new AllocInfo() { Array = array, Length = (ulong)array.Length, Handle = handle };
            return address;
        }

        /// <summary>
        /// This was originally CALL_MUNMAP and is used to release memory pages
        /// back to the OS.  This function works with pages, not with units
        /// individually allocated by CallMoreCore.  Therefore it could try to
        /// free part of an allocation or even multiple allocations at a time.
        /// Return true to indicate success, or false for failure (in which
        /// case the page is retained and used for future requests)
        /// </summary>
        unsafe protected override bool CallReleaseCore(void* address, ulong length)
        {
            if (mAllocations.TryGetValue((ulong)address, out var info) && info.Length == length)
            {
                info.Handle.Free();
                mAllocations.Remove((ulong)address);
                return true;
            }
            return false;
        }

        unsafe protected override void CallDisposeFinal()
        {
            base.CallDisposeFinal();
            foreach (var info in mAllocations)
                info.Value.Handle.Free();
            mAllocations.Clear();
        }

        public void Free(ArraySegment<byte> seg)
        {
            unsafe
            {
                fixed (byte* address = &seg.Array[seg.Offset])
                {
                    base.Free(address);
                }
            }
        }

        new public ArraySegment<byte> Malloc(ulong length)
        {
            unsafe
            {
                // NOTE: The search will be quick because of exponential heap growth
                var address = (ulong)base.Malloc(length);
                foreach (var info in mAllocations)
                {
                    if (address >= info.Key && address < info.Key + info.Value.Length)
                    {
                        return new ArraySegment<byte>(info.Value.Array, (int)(address - info.Key), (int)length);
                    }
                }
            }
            throw new DlMallocException("Could not find allocated array");
        }

    }
}
