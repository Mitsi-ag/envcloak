import Darwin

/// Paths come from the uid database, never the app's launch environment.
enum UserPaths {
    static func home() throws -> String {
        var record = passwd()
        var found: UnsafeMutablePointer<passwd>?
        var bytes = [CChar](repeating: 0, count: 16_384)
        let code = getpwuid_r(geteuid(), &record, &bytes, bytes.count, &found)
        guard code == 0, found != nil, let raw = record.pw_dir,
              let home = String(validatingCString: raw), home.hasPrefix("/") else {
            throw EnvCloakError.daemonUnverified(.path)
        }
        return home
    }
    static func runtime() throws -> String { try home() + "/Library/Application Support/EnvCloak/run" }
}

struct PeerSnapshot {
    let directory: stat
    let socket: stat
}

enum Peer {
    static func check(directory: String, uid: uid_t) throws -> PeerSnapshot {
        guard directory.hasPrefix("/"), !directory.utf8.contains(0),
              !(directory.split(separator: "/").contains("..")), !directory.hasSuffix("/") else {
            throw EnvCloakError.daemonUnverified(.path)
        }
        let path = directory + "/envcloakd.sock"
        guard path.utf8.count < 104 else { throw EnvCloakError.daemonUnverified(.path) }
        var dir = stat()
        guard lstat(directory, &dir) == 0 else { throw failure(.directoryType) }
        guard dir.st_mode & S_IFMT == S_IFDIR else { throw EnvCloakError.daemonUnverified(.directoryType) }
        guard dir.st_uid == uid else { throw EnvCloakError.daemonUnverified(.directoryOwner) }
        guard dir.st_mode & 0o022 == 0 else { throw EnvCloakError.daemonUnverified(.directoryMode) }
        let parent = String(directory.prefix(upTo: directory.lastIndex(of: "/")!))
        var p = stat()
        guard stat(parent.isEmpty ? "/" : parent, &p) == 0,
              p.st_mode & S_IFMT == S_IFDIR,
              p.st_uid == uid || p.st_uid == 0,
              p.st_mode & 0o022 == 0 || p.st_mode & S_ISVTX != 0 else {
            throw EnvCloakError.daemonUnverified(.parent)
        }
        var sock = stat()
        guard lstat(path, &sock) == 0 else { throw failure(.socketType) }
        guard sock.st_mode & S_IFMT == S_IFSOCK else { throw EnvCloakError.daemonUnverified(.socketType) }
        guard sock.st_uid == uid else { throw EnvCloakError.daemonUnverified(.socketOwner) }
        guard sock.st_mode & 0o777 == 0o600 else { throw EnvCloakError.daemonUnverified(.socketMode) }
        return PeerSnapshot(directory: dir, socket: sock)
    }

    static func verifyUID(fd: Int32, expected: uid_t) throws {
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == expected else {
            throw EnvCloakError.daemonUnverified(.peerUID)
        }
    }

    static func failure(_ check: PeerCheck) -> EnvCloakError {
        errno == ENOENT || errno == ECONNREFUSED ? .daemonUnavailable : .daemonUnverified(check)
    }

    static func unchanged(_ a: PeerSnapshot, _ b: PeerSnapshot) -> Bool {
        func same(_ x: stat, _ y: stat) -> Bool {
            x.st_dev == y.st_dev && x.st_ino == y.st_ino && x.st_uid == y.st_uid && x.st_mode == y.st_mode
        }
        return same(a.directory, b.directory) && same(a.socket, b.socket)
    }
}

/// Owned descriptor, confined to a worker. All I/O shares one monotonic
/// deadline; poll also observes cancellation, including during connect.
final class Connection {
    let fd: Int32
    let deadline: ContinuousClock.Instant

    init(directory: String, timeout: Duration, uid: uid_t = geteuid()) throws {
        deadline = ContinuousClock.now.advanced(by: timeout)
        let before = try Peer.check(directory: directory, uid: uid)
        fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw EnvCloakError.daemonUnavailable }
        do {
            var noSignal: Int32 = 1
            var time = timeval(tv_sec: 10, tv_usec: 0)
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
                  fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
                  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0,
                  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &time, socklen_t(MemoryLayout.size(ofValue: time))) == 0,
                  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &time, socklen_t(MemoryLayout.size(ofValue: time))) == 0 else {
                throw EnvCloakError.daemonUnverified(.socketOptions)
            }
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            let path = Array((directory + "/envcloakd.sock").utf8) + [0]
            withUnsafeMutablePointer(to: &address.sun_path) { pointer in
                pointer.withMemoryRebound(to: UInt8.self, capacity: 104) { target in
                    for i in path.indices { target[i] = path[i] }
                }
            }
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if result != 0 {
                guard errno == EINPROGRESS else { throw Peer.failure(.socketType) }
                try ready(POLLOUT)
                var error: Int32 = 0
                var size = socklen_t(MemoryLayout.size(ofValue: error))
                guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0, error == 0 else {
                    throw EnvCloakError.daemonUnavailable
                }
            }
            try Peer.verifyUID(fd: fd, expected: uid)
            let after = try Peer.check(directory: directory, uid: uid)
            guard Peer.unchanged(before, after) else { throw EnvCloakError.daemonUnverified(.changed) }
            // M3-10 adds the pinned audit-token code-identity check here,
            // before this connection can be used by any method.
        } catch {
            // All stored properties are initialized, so Swift runs deinit
            // on this throw too. It is the descriptor's only closer.
            throw error
        }
    }

    deinit { Darwin.close(fd) }

    func ready(_ event: Int32) throws {
        while true {
            guard !Task.isCancelled, ContinuousClock.now < deadline else { throw EnvCloakError.protocolError }
            let left = ContinuousClock.now.duration(to: deadline).components
            let millis = max(1, min(50, left.seconds * 1000 + left.attoseconds / 1_000_000_000_000_000))
            var descriptor = pollfd(fd: fd, events: Int16(event), revents: 0)
            let result = poll(&descriptor, 1, Int32(millis))
            if result > 0 {
                guard descriptor.revents & Int16(POLLNVAL) == 0 else { throw EnvCloakError.protocolError }
                return
            }
            if result < 0, errno != EINTR { throw EnvCloakError.protocolError }
        }
    }

    func read(_ bytes: UnsafeMutableRawBufferPointer) throws -> Int {
        while true {
            try ready(POLLIN)
            let n = recv(fd, bytes.baseAddress, bytes.count, 0)
            if n >= 0 { return n }
            if errno != EINTR && errno != EAGAIN { throw EnvCloakError.protocolError }
        }
    }

    func write(_ bytes: UnsafeRawBufferPointer) throws -> Int {
        while true {
            try ready(POLLOUT)
            let n = send(fd, bytes.baseAddress, bytes.count, 0)
            if n >= 0 { return n }
            if errno != EINTR && errno != EAGAIN { throw EnvCloakError.protocolError }
        }
    }
}
