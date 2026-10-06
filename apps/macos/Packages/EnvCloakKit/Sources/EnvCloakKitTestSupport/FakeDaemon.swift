import Darwin
import Foundation

/// A real Unix listener in an owned short runtime directory. It records
/// every received byte, including bytes sent before an intended refusal.
public final class FakeDaemon: @unchecked Sendable {
    public let directory: String
    private let listener: Int32
    private let lock = NSLock()
    private var connections: [Int32] = []
    private var records: [[UInt8]] = []
    private let group = DispatchGroup()
    private let handler: @Sendable ([UInt8]) -> [UInt8]?
    private var stopped = false

    public init(directory: String, handler: @escaping @Sendable ([UInt8]) -> [UInt8]?) throws {
        self.directory = directory
        self.handler = handler
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw FixtureError.io }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let path = Array((directory + "/envcloakd.sock").utf8) + [0]
        guard path.count <= 104 else { close(listener); throw FixtureError.io }
        withUnsafeMutablePointer(to: &address.sun_path) {
            $0.withMemoryRebound(to: UInt8.self, capacity: 104) { p in
                for i in path.indices { p[i] = path[i] }
            }
        }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, chmod(directory + "/envcloakd.sock", 0o600) == 0, listen(listener, 8) == 0,
              fcntl(listener, F_SETFL, O_NONBLOCK) == 0 else { close(listener); throw FixtureError.io }
        group.enter()
        DispatchQueue.global().async { [self] in
            defer { group.leave() }
            while !lock.withLock({ stopped }) {
                var p = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
                if poll(&p, 1, 20) <= 0 { continue }
                let fd = accept(listener, nil, nil)
                if fd < 0 { continue }
                _ = fcntl(fd, F_SETFL, 0)
                var noSignal: Int32 = 1
                _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout.size(ofValue: noSignal)))
                let index = lock.withLock { connections.append(fd); records.append([]); return records.count - 1 }
                group.enter()
                DispatchQueue.global().async { [self] in
                    defer { group.leave() }
                    var received: [UInt8] = []
                    var buffer = [UInt8](repeating: 0, count: 4096)
                    while true {
                        let n = recv(fd, &buffer, buffer.count, 0)
                        if n <= 0 { break }
                        received += buffer.prefix(n)
                        lock.withLock { records[index] = received }
                        if received.count >= 4 {
                            let expected = received.prefix(4).reduce(0) { $0 * 256 + Int($1) }
                            if received.count >= 4 + expected {
                                if let response = handler(Array(received.dropFirst(4))) {
                                    var offset = 0
                                    while offset < response.count {
                                        let sent = response.withUnsafeBytes { send(fd, $0.baseAddress!.advanced(by: offset), response.count - offset, 0) }
                                        if sent <= 0 { break }
                                        offset += sent
                                    }
                                }
                                break
                            }
                        }
                    }
                    lock.withLock {
                        _ = close(fd)
                        connections.removeAll { $0 == fd }
                    }
                }
            }
        }
    }

    public var received: [[UInt8]] { lock.withLock { records } }
    public func stop() {
        let wasStopped = lock.withLock { stopped }
        if wasStopped { return }
        lock.withLock {
            stopped = true
            for fd in connections { _ = shutdown(fd, SHUT_RDWR) }
        }
        group.wait()
        _ = close(listener)
    }
    public static func frame(_ text: String) -> [UInt8] {
        let body = Array(text.utf8)
        return (0..<4).map { UInt8(truncatingIfNeeded: body.count >> (24 - $0 * 8)) } + body
    }
}

public enum FixtureError: Error { case io }
