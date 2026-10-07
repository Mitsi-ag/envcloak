import Darwin
import Foundation

/// Filesystem metadata is a separate change signal from the vault audit.
/// Observe the directory as well as the file to catch atomic replacement;
/// ctime catches an in-place rewrite even when size and mtime are restored.
struct ManifestSignal: Equatable {
    private let stamps: [[Int64]]
    var fileMissing: Bool { stamps.last == [-1, Int64(ENOENT)] }
    init(directory: URL) {
        stamps = [directory, directory.appendingPathComponent("envcloak.toml")].map { url in
            var info = stat()
            guard lstat(url.path, &info) == 0 else { return [-1, Int64(errno)] }
            return [Int64(info.st_dev), Int64(bitPattern: info.st_ino), Int64(info.st_mode), info.st_size,
                    Int64(info.st_mtimespec.tv_sec), Int64(info.st_mtimespec.tv_nsec),
                    Int64(info.st_ctimespec.tv_sec), Int64(info.st_ctimespec.tv_nsec)]
        }
    }
}
