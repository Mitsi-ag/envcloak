import CoreText
import Foundation

/// Martian Mono, bundled with the app (docs/BRAND.md §4): the variable font
/// `MartianMono[wdth,wght].ttf` from google/fonts, kept as
/// Resources/Fonts/MartianMono.ttf with its licence beside it
/// (THIRD_PARTY_NOTICES.md). `ECFont.martianMono(size:weight:width:)` in
/// EnvCloakMotion.swift asks for the family by name, so the font must be
/// registered for this process before the first view that uses it is drawn.
public enum ECFonts {
    /// The family name `ECFont` asks for.
    public static let martianMonoFamily = "Martian Mono"

    /// Registers the bundled Martian Mono for this process on first use and
    /// says whether it is available. Registration happens once; a font this
    /// process already registered counts as available.
    public static let martianMonoRegistered: Bool = register()

    /// The bundled font file.
    public static var martianMonoURL: URL? {
        ECDesign.bundle.url(forResource: "MartianMono", withExtension: "ttf", subdirectory: "Fonts")
    }

    /// The font's licence, the SIL Open Font License 1.1, which travels
    /// with every copy of the font.
    public static var martianMonoLicenceURL: URL? {
        ECDesign.bundle.url(forResource: "MartianMono-OFL", withExtension: "txt", subdirectory: "Fonts")
    }

    private static func register() -> Bool {
        guard let url = martianMonoURL else { return false }
        var error: Unmanaged<CFError>?
        if CTFontManagerRegisterFontsForURL(url as CFURL, .process, &error) {
            return true
        }
        guard let failure = error?.takeRetainedValue() else { return false }
        return CFErrorGetCode(failure) == CTFontManagerError.alreadyRegistered.rawValue
    }
}
