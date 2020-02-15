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
using Gosub.DlMalloc;

// The original dlmalloc http://gee.cs.oswego.edu/dl/html/malloc.html was
// placed into the public domain by Doug Lea as explained in the comments:
//
//      This is a version (aka dlmalloc) of malloc/free/realloc written by
//      Doug Lea and released to the public domain, as explained at
//      http://creativecommons.org/publicdomain/zero/1.0/ Send questions,
//      comments, complaints, performance data, etc to dl@cs.oswego.edu
//

namespace Gosub.DlMallocTest
{

    class Program
    {
        unsafe static void Main(string[] args)
        {
            var time = DateTime.Now;
            var test = new DlMallocTest();
            test.Test();
            MemoryExample();
            SegmentExample();
            Console.WriteLine("Time = " + (DateTime.Now-time));
            Console.WriteLine("Press ENTER to exit");
            Console.ReadLine();
        }

        // Create just one instance of the allocator
        static DlMallocMemory sMallocMemory = new DlMallocMemory();

        unsafe static void MemoryExample()
        {
            byte* memory = (byte*)sMallocMemory.Malloc(256);
            // Use the memory, then eventually free it
            sMallocMemory.Free(memory);
        }

        // Create just one instance of the allocator
        static DlMallocSegment sMallocSegment = new DlMallocSegment();

        static void SegmentExample()
        {
            ArraySegment<byte> memory = sMallocSegment.Malloc(256);
            // Use the memory, then eventually free it
            sMallocSegment.Free(memory);
        }

    }
}
