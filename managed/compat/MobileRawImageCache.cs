using System;
using System.Collections.Generic;
using System.IO;

namespace TerrariaMobile.Serialization;

// CPU resident cache only. Returned immutable images may outlive eviction;
// this budget does not include references retained by callers or GPU memory.
public sealed class MobileRawImageCache : IDisposable
{
    private readonly int budget, maxDimension;
    private readonly object gate = new();
    private readonly Dictionary<(string Hash, string Entry), LinkedListNode<Cached>> entries = new();
    private readonly LinkedList<Cached> lru = new();
    private int residentBytes;
    private bool disposed;
    private sealed record Cached((string Hash, string Entry) Key, MobileRawImage Image);

    public MobileRawImageCache(int maxResidentBytes = 16 * 1024 * 1024, int maxDimension = 8192)
    {
        if (maxResidentBytes <= 0 || maxResidentBytes > MobileTmodArchive.MaxEntryBytes ||
            maxDimension <= 0 || maxDimension > 32768) throw new ArgumentOutOfRangeException();
        budget = maxResidentBytes; this.maxDimension = maxDimension;
    }
    public int ResidentBytes { get { lock (gate) return residentBytes; } }
    public int Count { get { lock (gate) return entries.Count; } }

    public MobileRawImage Get(MobileTmodArchive archive, string entry)
    {
        lock (gate)
        {
            if (disposed) throw new ObjectDisposedException(nameof(MobileRawImageCache));
            if (archive == null) throw new ArgumentNullException(nameof(archive));
            if (entry == null || !entry.EndsWith(".rawimg", StringComparison.Ordinal))
                throw new ArgumentException("Expected explicit rawimg entry", nameof(entry));
            if (!archive.HasFile(entry)) throw new FileNotFoundException("Raw image entry missing", entry);
            var key = (archive.Sha256, entry.Replace('\\', '/'));
            if (entries.TryGetValue(key, out var cached))
            {
                lru.Remove(cached); lru.AddFirst(cached); return cached.Value.Image;
            }
            // A failed read leaves existing cache entries and eviction order unchanged.
            var image = MobileRawImage.FromArchive(archive, entry, maxDimension, budget);
            while (residentBytes > budget - image.PixelByteCount)
            {
                var last = lru.Last;
                entries.Remove(last.Value.Key); residentBytes -= last.Value.Image.PixelByteCount;
                lru.RemoveLast();
            }
            var node = lru.AddFirst(new Cached(key, image)); entries.Add(key, node);
            residentBytes += image.PixelByteCount;
            return image;
        }
    }
    public void Clear()
    {
        lock (gate) { entries.Clear(); lru.Clear(); residentBytes = 0; }
    }
    public void Dispose()
    {
        lock (gate) { Clear(); disposed = true; }
    }
}
