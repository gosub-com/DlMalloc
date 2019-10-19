# Malloc in C#

This is a port of [DlMalloc by Doug Lea](http://gee.cs.oswego.edu/dl/html/malloc.html)
into C#.

The original source code is here, [dlmalloc.c](dlmalloc.c.original.txt), and the result of the
port is here: [DlMallocBase.cs](DlMalloc/DlMallocBase.cs).  This base class is used
to create two allocators, a memory alloctor and an array segment allocator.

## Memory allocator: [DlMallocMemory.cs](DlMalloc/DlMallocMemory.cs)

The memory allocator works just like malloc in C and can be used only in unsafe
code.  An example of how to use this allocator:

```
        // Create just one instance of the allocator
        static DlMallocMemory sMallocMemory = new DlMallocMemory();

        unsafe static void MemoryExample()
        {
            byte* memory = (byte*)sMallocMemory.Malloc(256);
            // Use the memory, then eventually free it
            sMallocMemory.Free(memory);
        }
```


## Array Segment Allocator: [DlMallocSegment.cs](DlMalloc/DlMallocSegment.cs)

The array segment allocator works with `ArraySegment<byte>` and can be used
in safe code (although, the class itself is unsafe):

```
        // Create just one instance of the allocator
        static DlMallocSegment sMallocSegment = new DlMallocSegment();

        static void SegmentExample()
        {
            ArraySegment<byte> memory = sMallocSegment.Malloc(256);
            // Use the memory, then eventually free it
            sMallocSegment.Free(memory);
        }
```

## Thread safety considerations

Not thread safe.  If you use DLMalloc C# in a multi-threaded environment,
be sure to `lock` all uses of `Malloc` and `Free`.  Or better yet, wrap
it all in a `DlMallocThreadSafe` class.

## CPU considerations

DlMalloc C# will run on either 32 bit or 64 bit systems by detecting the
pointer size at runtime.

## Port Info

I stripped out a lot of unused functionality.  `CALL_MORECORE` (a pass through
to sbrk) is gone and replaced by just `CALL_MMAP` and `CALL_MUNMAP` which has
become `CallMoreCore` and `CallReleaseCore`.

`size_t` has been left in place, but is now always 64 bits on all systems.
There are many places where the C# code could be changed to use uint
or ulong, but since the original code uses `size_t` everywhere it was easier
to leave it as-is and use 64 bits everywhere.

There is still a lot that could be improved and made to look more C# like,
but this is all for now.






