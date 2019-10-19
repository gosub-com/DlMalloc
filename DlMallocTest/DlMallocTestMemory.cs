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
using System.Runtime.InteropServices;
using Gosub.DlMalloc;

namespace Gosub.DlMallocTest
{
    /// <summary>
    /// This class provides access to underlying properties used
    /// to test DlMalloc and also provides a switch to use
    /// pre-allocated memory to test page coalescence
    /// </summary>
    unsafe class DlMallocTestMemory : DlMallocMemory
    {
        const int PRE_ALLOCATED_SIZE = 100000000;
        IntPtr mAllocatedMemory;
        ulong mAllocatedMemoryIndex;

        public DlMallocTestMemory()
        {
            ClearMemoryBeforeReleasing = true;
        }

        new public void Trim(ulong pad = 0) { base.Trim(pad); }

        /// <summary>
        /// Pre-allocates 100Mb, then uses that memory for all allocations
        /// </summary>
        public bool PreAllocate
        {
            get { return mAllocatedMemory != IntPtr.Zero; }
            set
            {
                if (PreAllocate == value)
                    return;
                if (value)
                {
                    mAllocatedMemory = Marshal.AllocHGlobal(PRE_ALLOCATED_SIZE);
                }
                else
                {
                    Marshal.FreeHGlobal(mAllocatedMemory);
                    mAllocatedMemory = IntPtr.Zero;
                }
            }
        }

        /// <summary>
        /// Set to true to force the release core to fail
        /// </summary>
        public bool ForceFailReleaseCore;

        protected override void CallDisposeFinal()
        {
            PreAllocate = false;
            base.CallDisposeFinal();
        }

        protected override unsafe void* CallMoreCore(ref ulong length)
        {
            if (PreAllocate)
            {
                var m = (void*)((byte*)mAllocatedMemory + mAllocatedMemoryIndex);
                mAllocatedMemoryIndex += length;
                if (mAllocatedMemoryIndex >= PRE_ALLOCATED_SIZE)
                    throw new DlMallocException("Out of pre-allocated memory while testing");
                return m;
            }
            return base.CallMoreCore(ref length);
        }

        protected override unsafe bool CallReleaseCore(void* address, ulong length)
        {
            if (ForceFailReleaseCore)
                return false;

            if (PreAllocate)
            {
                MemClear(address, (long)length);
                return true;
            }
            return base.CallReleaseCore(address, length);
        }


    }
}
