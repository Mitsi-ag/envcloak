import Darwin

/// Unique page allocation. Only the initialized prefix may be exposed;
/// growth and destruction wipe the whole allocation before releasing it.
public struct SecretBuffer: ~Copyable, @unchecked Sendable {
    private var region: UnsafeMutableRawPointer
    private var allocation: Int
    public private(set) var count = 0
    public var capacity: Int { allocation }
    public var description: String { "[secret]" }
    public var debugDescription: String { "[secret]" }
    #if DEBUG
    private var observer: ((UnsafeRawBufferPointer) -> Void)?
    #endif

    public init(capacity: Int = 0) throws(EnvCloakError) {
        guard MemoryHardening.coreDisabled, (0...Frame.limit).contains(capacity) else {
            throw .protocolError
        }
        let page = Int(getpagesize())
        let allocated = max(page, ((capacity + page - 1) / page) * page)
        guard let p = mmap(nil, allocated, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0),
              p != MAP_FAILED else { throw .protocolError }
        allocation = allocated
        region = p
        #if DEBUG
        observer = BufferProbe.observer?.callback
        #endif
        // Best effort: failure to lock pages is a documented limit.
        _ = mlock(region, allocation)
    }

    #if DEBUG
    init(capacity: Int, wipeObserver: @escaping (UnsafeRawBufferPointer) -> Void) throws(EnvCloakError) {
        try self.init(capacity: capacity)
        observer = wipeObserver
    }
    #endif

    deinit { release() }

    private borrowing func release() {
        // memset_s cannot be elided as a dead store, including in Release.
        _ = memset_s(region, allocation, 0, allocation)
        #if DEBUG
        observer?(UnsafeRawBufferPointer(start: region, count: allocation))
        #endif
        _ = munlock(region, allocation)
        _ = munmap(region, allocation)
    }

    public mutating func reserveCapacity(_ requested: Int) throws(EnvCloakError) {
        guard (0...Frame.limit).contains(requested) else { throw .protocolError }
        if requested <= capacity { return }
        var next = try SecretBuffer(capacity: requested)
        #if DEBUG
        next.observer = observer
        #endif
        next.region.copyMemory(from: region, byteCount: count)
        next.count = count
        self = consume next
    }

    public borrowing func withUnsafeBytes<R: ~Copyable>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: region, count: count))
    }

    public mutating func append(contentsOf bytes: UnsafeRawBufferPointer) throws(EnvCloakError) {
        guard bytes.count <= Frame.limit - count else { throw .protocolError }
        if count + bytes.count > capacity {
            try reserveCapacity(min(Frame.limit, max(count + bytes.count, capacity * 2)))
        }
        if let base = bytes.baseAddress { region.advanced(by: count).copyMemory(from: base, byteCount: bytes.count) }
        count += bytes.count
    }

    mutating func append(contentsOf bytes: [UInt8]) throws {
        try bytes.withUnsafeBytes { try append(contentsOf: $0) }
    }

    mutating func append(_ byte: UInt8) throws(EnvCloakError) {
        guard count < Frame.limit else { throw .protocolError }
        if count == capacity { try reserveCapacity(min(Frame.limit, capacity * 2)) }
        region.storeBytes(of: byte, toByteOffset: count, as: UInt8.self)
        count += 1
    }

    mutating func read(upTo maximum: Int, using read: (UnsafeMutableRawBufferPointer) throws -> Int) throws -> Int {
        guard maximum > 0, maximum <= capacity - count else { throw EnvCloakError.protocolError }
        let got = try read(UnsafeMutableRawBufferPointer(start: region.advanced(by: count), count: maximum))
        guard (0...maximum).contains(got) else { throw EnvCloakError.protocolError }
        count += got
        return got
    }
}

private enum MemoryHardening {
    static let coreDisabled: Bool = {
        var limit = rlimit(rlim_cur: 0, rlim_max: 0)
        return setrlimit(RLIMIT_CORE, &limit) == 0
    }()
}

#if DEBUG
// Task-local, so one parallel test never observes another test's buffers.
final class BufferObserver: Sendable {
    let callback: @Sendable (UnsafeRawBufferPointer) -> Void
    init(_ callback: @escaping @Sendable (UnsafeRawBufferPointer) -> Void) { self.callback = callback }
}
enum BufferProbe {
    @TaskLocal static var observer: BufferObserver?
}
#endif
