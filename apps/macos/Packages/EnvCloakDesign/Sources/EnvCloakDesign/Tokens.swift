import AppKit
import SwiftUI

/// The bundle that holds the design resources: the colour asset catalog,
/// the menu bar template and the bundled fonts.
public enum ECDesign {
    public static let bundle: Bundle = .module
}

/// The app's colour tokens (docs/APP.md "Design tokens", from docs/BRAND.md
/// §3). Each is a named colour in Resources/Colors.xcassets with a light, a
/// dark and an Increase Contrast value for each, so views never hold a
/// literal colour (M3 plan §5 rule 5, checked by scripts/macos/check-swift.sh).
/// Controls keep the system accent colour: EnvCloak sets no AccentColor.
public enum ECToken: String, CaseIterable, Sendable {
    /// Window and sheet content.
    case background
    /// Code blocks, the value row, footers.
    case raised
    /// Body text and marks.
    case text
    /// Captions and metadata.
    case secondary
    /// Decorative dividers only, never the only edge of a control.
    case rule
    /// With `checkmark.circle` and a word.
    case success
    /// With `exclamationmark.triangle` and a word.
    case warning
    /// With `xmark.octagon` and a word; real failures only.
    case danger
    /// With `info.circle` and a word.
    case info
    /// The held value, only ever on Ink (`plate`, or the dark appearance).
    case amber
    /// The approval mark's plate.
    case plate

    /// The token as a SwiftUI colour, resolved for the current appearance.
    public var color: Color {
        Color(rawValue, bundle: ECDesign.bundle)
    }

    /// The token as an AppKit colour, or nil if the asset catalog lacks it
    /// (a test checks that none is missing).
    public var nsColor: NSColor? {
        NSColor(named: rawValue, bundle: ECDesign.bundle)
    }
}

/// Images the app takes from the brand kit (assets/brand/).
public enum ECImage {
    /// The menu bar extra's icon: a template image the system tints, never
    /// the colour app icon (assets/brand/icon/menubar/).
    public static let menuTemplateName = "EnvCloakMenuTemplate"

    public static var menuTemplate: Image {
        Image(menuTemplateName, bundle: ECDesign.bundle).renderingMode(.template)
    }

    /// The same image through AppKit, or nil if the asset catalog lacks it.
    public static var menuTemplateNSImage: NSImage? {
        ECDesign.bundle.image(forResource: menuTemplateName)
    }
}
