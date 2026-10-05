import os

/// A word the app may write to the unified log.
///
/// The app logs only through `Logger` (SPEC §5 "Logging"). `Logger` keeps an
/// interpolated value private by default, but whoever starts the app can
/// undo that: with `OS_ACTIVITY_DT_MODE=YES` in its environment (`open
/// --env`, `launchctl submit`, `xcodebuild test`) the log stores private
/// arguments in the clear (docs/APP.md "Logging"). So the app interpolates
/// nothing but tokens into a log message: scripts/macos/check-swift.sh
/// refuses any other interpolation in a log call, lets only an `enum`
/// conform to `LogToken`, and lets only this file declare `logToken`.
/// Whatever reaches the log is one of a fixed set of raw values written in
/// the source: never a value, a name, a path or anything the daemon sent.
public protocol LogToken: RawRepresentable, Sendable where RawValue == String {}

extension LogToken {
    /// The token's fixed text, the only expression a log message may hold.
    public var logToken: String { rawValue }
}

/// The app's log: subsystem `ai.envcloak.app`, one category per area.
public enum ECLog {
    public static let subsystem = "ai.envcloak.app"

    public static func logger(_ category: ECLogCategory) -> Logger {
        Logger(subsystem: subsystem, category: category.rawValue)
    }
}

/// The log categories. Each is a fixed word, like a `LogToken`.
public enum ECLogCategory: String, Sendable {
    case app
    case client
}
