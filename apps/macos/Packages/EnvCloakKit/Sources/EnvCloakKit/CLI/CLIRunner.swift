import Darwin
import Foundation

#if DEBUG
final class CLITestHooks: Sendable {
    let now: @Sendable () -> ContinuousClock.Instant
    let beforeResult: @Sendable () -> Void
    init(now: @escaping @Sendable () -> ContinuousClock.Instant, beforeResult: @escaping @Sendable () -> Void) {
        self.now = now; self.beforeResult = beforeResult
    }
}
enum CLIProbe { @TaskLocal static var hooks: CLITestHooks? }
#endif

public enum CLIError: Error, Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    case invalidArguments, unavailable, failed(Int32), timedOut, outputLimit, invalidOutput
    public var description: String {
        switch self {
        case .invalidArguments: "invalid_arguments"
        case .unavailable: "cli_unavailable"
        case .failed: "cli_failed"
        case .timedOut: "cli_timed_out"
        case .outputLimit: "cli_output_limit"
        case .invalidOutput: "cli_invalid_output"
        }
    }
    public var debugDescription: String { description }
}

public struct CLIResult: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    /// JSON from a metadata-only CLI command, never stderr.
    public let json: String
    public var description: String { "[cli result]" }
    public var debugDescription: String { description }
}

/// The bundle's CLI, with no shell, inherited environment or terminal.
/// The uid database supplies HOME. Fixture paths are internal only.
public struct CLIRunner: Sendable {
    private let executable: String
    private let home: String
    private let timeout: Duration

    public init() throws {
        executable = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/envcloak").path
        home = try UserPaths.home()
        timeout = .seconds(30)
    }
    init(executable: String, home: String, timeout: Duration) {
        self.executable = executable; self.home = home; self.timeout = timeout
    }

    public func run(arguments: [String], workingDirectory: String) async throws -> CLIResult {
        // These commands emit metadata. Value and proof flows use typed IPC.
        guard let first = arguments.first, ["ref", "check", "agents", "daemon"].contains(first),
              workingDirectory.hasPrefix("/"), !workingDirectory.utf8.contains(0),
              arguments.allSatisfy({ !$0.utf8.contains(0) }) else { throw CLIError.invalidArguments }
        let operation: @Sendable () throws -> CLIResult = { try execute(arguments: arguments, directory: workingDirectory) }
        #if DEBUG
        let hooks = CLIProbe.hooks
        let worker = Task.detached { try CLIProbe.$hooks.withValue(hooks, operation: operation) }
        #else
        let worker = Task.detached(operation: operation)
        #endif
        let result = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
        guard !Task.isCancelled else { throw CLIError.timedOut }
        return result
    }

    private static var now: ContinuousClock.Instant {
        #if DEBUG
        if let hooks = CLIProbe.hooks { return hooks.now() }
        #endif
        return ContinuousClock.now
    }

    private func execute(arguments: [String], directory: String) throws -> CLIResult {
        let deadline = Self.now.advanced(by: timeout)
        var out = [Int32](repeating: -1, count: 2)
        var err = [Int32](repeating: -1, count: 2)
        guard pipe(&out) == 0 else { throw CLIError.unavailable }
        defer { for fd in out where fd >= 0 { close(fd) } }
        guard pipe(&err) == 0 else { throw CLIError.unavailable }
        defer { for fd in err where fd >= 0 { close(fd) } }
        for fd in out + err {
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw CLIError.unavailable }
        }
        for fd in [out[0], err[0]] {
            guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw CLIError.unavailable }
        }
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw CLIError.unavailable }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw CLIError.unavailable }
        defer { posix_spawnattr_destroy(&attributes) }
        var mask = sigset_t()
        sigemptyset(&mask)
        var defaults = sigset_t()
        sigfillset(&defaults)
        guard posix_spawnattr_setpgroup(&attributes, 0) == 0,
              posix_spawnattr_setsigmask(&attributes, &mask) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0,
              posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0) == 0,
              posix_spawn_file_actions_adddup2(&actions, out[1], 1) == 0,
              posix_spawn_file_actions_adddup2(&actions, err[1], 2) == 0,
              posix_spawn_file_actions_addchdir(&actions, directory) == 0 else { throw CLIError.unavailable }
        let argv = [executable] + arguments + (arguments.contains("--json") ? [] : ["--json"])
        let environment = ["HOME=" + home, "PATH=/usr/bin:/bin", "LANG=en_US.UTF-8"]
        var args = argv.map { strdup($0) } + [nil]
        var env = environment.map { strdup($0) } + [nil]
        defer { for pointer in args + env { free(pointer) } }
        guard args.dropLast().allSatisfy({ $0 != nil }), env.dropLast().allSatisfy({ $0 != nil }) else { throw CLIError.unavailable }
        var pid: pid_t = 0
        guard posix_spawn(&pid, executable, &actions, &attributes, &args, &env) == 0 else { throw CLIError.unavailable }
        close(out[1]); out[1] = -1
        close(err[1]); err[1] = -1
        // This code is the only reaper. Keep the leader unreaped until
        // both pipes finish, so timeout/cancellation may safely kill its
        // process group, including descendants retaining a pipe.
        var reaped = false
        defer {
            if !reaped {
                _ = kill(-pid, SIGKILL)
                var status: Int32 = 0
                while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
            }
        }
        var output: [UInt8] = []
        var total = 0
        var open = [true, true]
        var exited = false
        var status: Int32 = 0
        while !exited || open.contains(true) {
            guard !Task.isCancelled, Self.now < deadline else { throw CLIError.timedOut }
            var pollers = [out[0], err[0]].enumerated().map {
                pollfd(fd: open[$0.offset] ? $0.element : -1, events: Int16(POLLIN), revents: 0)
            }
            let ready = poll(&pollers, 2, 20)
            if ready < 0 && errno != EINTR { throw CLIError.unavailable }
            for index in 0..<2 where open[index] && pollers[index].revents != 0 {
                var bytes = [UInt8](repeating: 0, count: 8192)
                let count = read(pollers[index].fd, &bytes, bytes.count)
                if count == 0 { open[index] = false }
                if count > 0 {
                    total += count
                    guard total <= Frame.limit else { throw CLIError.outputLimit }
                    if index == 0 { output += bytes.prefix(count) }
                }
                if count < 0 && errno != EINTR && errno != EAGAIN { throw CLIError.unavailable }
            }
            var info = siginfo_t()
            guard waitid(P_PID, id_t(pid), &info, WEXITED | WNOHANG | WNOWAIT) == 0 else { throw CLIError.unavailable }
            exited = info.si_pid == pid
        }
        while waitpid(pid, &status, 0) < 0 {
            if errno != EINTR { throw CLIError.unavailable }
        }
        reaped = true
        guard status == 0 else { throw CLIError.failed(status) }
        do {
            try output.withUnsafeBytes { bytes in
                var parser = JSONParser(bytes: bytes)
                guard case .object = try parser.parse() else { throw CLIError.invalidOutput }
            }
        } catch { throw CLIError.invalidOutput }
        guard let json = String(bytes: output, encoding: .utf8) else { throw CLIError.invalidOutput }
        #if DEBUG
        CLIProbe.hooks?.beforeResult()
        #endif
        guard !Task.isCancelled, Self.now < deadline else { throw CLIError.timedOut }
        return CLIResult(json: json)
    }
}
