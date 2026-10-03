// EnvCloakMotion.swift
// Reference SwiftUI implementation of the EnvCloak motion set. The numbers come from assets/brand/motion/SPEC.md.
//
// Each timed moment is a pure function of elapsed time (RevealTimeline, RedactionTimeline), sampled by a
// TimelineView, so the app matches the web keyframes frame for frame and the timelines can be unit tested.
// Needs macOS 14 or later (UnitCurve, KeyframeAnimator). Type-checked against the macOS 26 SDK.

import AppKit
import SwiftUI

// MARK: - Tokens

public enum ECMotion {
    /// Caret half period in seconds: 530 ms on, 530 ms off, hard cuts.
    public static let caret: Double = 0.530
    /// The = being drawn: cubic-bezier(0.5, 0, 0, 1).
    public static let draw = UnitCurve.bezier(startControlPoint: UnitPoint(x: 0.5, y: 0),
                                              endControlPoint: UnitPoint(x: 0, y: 1))
    /// Arrivals and collapses: cubic-bezier(0.2, 0, 0, 1).
    public static let settle = UnitCurve.bezier(startControlPoint: UnitPoint(x: 0.2, y: 0),
                                                endControlPoint: UnitPoint(x: 0, y: 1))
    /// Symmetric in-out for the pulse return and reduced-motion fades: cubic-bezier(0.45, 0, 0.55, 1).
    public static let breathe = UnitCurve.bezier(startControlPoint: UnitPoint(x: 0.45, y: 0),
                                                 endControlPoint: UnitPoint(x: 0.55, y: 1))
    /// Opacity of the empty block (the loader's track).
    public static let ghost: Double = 0.2

    /// Eased progress of the segment [start, end] at time t, in seconds: 0 before it, 1 after it.
    public static func segment(_ t: Double, _ start: Double, _ end: Double, _ curve: UnitCurve) -> Double {
        if t <= start { return 0 }
        if t >= end { return 1 }
        return curve.value(at: (t - start) / (end - start))
    }

    /// The sign-off every sequence ends with. From `from`, the block is on for 530 ms, off, on, off,
    /// then on for good: two blinks, then still.
    public static func signOffVisible(_ t: Double, from: Double) -> Bool {
        guard t >= from else { return true }
        let beat = Int(((t - from) / caret).rounded(.down))
        return beat >= 4 || beat % 2 == 0
    }
}

// MARK: - Colour

public struct ECRGB: Equatable, Sendable {
    public var r: Double, g: Double, b: Double
    public init(_ hex: UInt32) {
        r = Double((hex >> 16) & 0xFF) / 255
        g = Double((hex >> 8) & 0xFF) / 255
        b = Double(hex & 0xFF) / 255
    }
    public init(r: Double, g: Double, b: Double) { self.r = r; self.g = g; self.b = b }
    /// sRGB mix, the same interpolation the CSS keyframes use. k = 0 gives self, 1 gives other.
    public func mix(_ other: ECRGB, _ k: Double) -> ECRGB {
        ECRGB(r: r + (other.r - r) * k, g: g + (other.g - g) * k, b: b + (other.b - b) * k)
    }
    public var color: Color { Color(.sRGB, red: r, green: g, blue: b) }
}

public enum ECColor {
    public static let ink = ECRGB(0x111110)
    public static let paper = ECRGB(0xF3F0E8)
    public static let amber = ECRGB(0xFFB000)       // only ever on Ink
    public static let darkTile = ECRGB(0x0B0B0A)    // dark appearance plate
    public static let darkEquals = ECRGB(0xDCD8CE)  // dark appearance =
}

public enum ECFont {
    /// Martian Mono (SIL OFL 1.1) at a given weight and width. Bundle MartianMono[wdth,wght].ttf from
    /// google/fonts with its licence (assets/brand/fonts/MartianMono-OFL.txt) and list it under ATSApplicationFontsPath (or register it with
    /// CTFontManager). Code text uses weight 400, width 87.5, which gives a 0.65 em advance.
    public static func martianMono(size: CGFloat, weight: CGFloat = 400, width: CGFloat = 87.5) -> Font {
        let wght = 0x7767_6874   // 'wght'
        let wdth = 0x7764_7468   // 'wdth'
        let descriptor = NSFontDescriptor(fontAttributes: [
            .family: "Martian Mono",
            .variation: [NSNumber(value: wght): weight, NSNumber(value: wdth): width],
        ])
        let font = NSFont(descriptor: descriptor, size: size) ?? .monospacedSystemFont(ofSize: size, weight: .regular)
        return Font(font as CTFont)
    }
}

// MARK: - Symbol

/// The symbol on its module grid: bars 3s x s, block 3s x 5s, every gap s, radius s/4.
/// At s <= 2 pt (the 16 pt size) corners are square, as in the hinted SVG.
public struct ECSymbol: View {
    public var module: CGFloat
    public var equalsColor: Color
    public var blockColor: Color
    public var topBar: Double = 1          // wipe progress of the top bar, 0...1
    public var lowBar: Double = 1          // wipe progress of the low bar, 0...1
    public var blockOpacity: Double = 1
    public var blockScale: CGFloat = 1
    public var level: Double = 1           // bottom-up fill of the block, 0...1
    public var showsTrack = false          // ghost of the empty block under the level

    public init(module: CGFloat, equalsColor: Color, blockColor: Color, topBar: Double = 1, lowBar: Double = 1,
                blockOpacity: Double = 1, blockScale: CGFloat = 1, level: Double = 1, showsTrack: Bool = false) {
        self.module = module
        self.equalsColor = equalsColor
        self.blockColor = blockColor
        self.topBar = topBar
        self.lowBar = lowBar
        self.blockOpacity = blockOpacity
        self.blockScale = blockScale
        self.level = level
        self.showsTrack = showsTrack
    }

    private var radius: CGFloat { module <= 2 ? 0 : module / 4 }

    public var body: some View {
        let s = module
        HStack(spacing: s) {
            VStack(spacing: s) {
                bar(topBar)
                bar(lowBar)
            }
            ZStack(alignment: .bottom) {
                if showsTrack {
                    block.opacity(ECMotion.ghost)
                }
                block
                    .mask(alignment: .bottom) {
                        Rectangle().frame(height: 5 * s * level)
                    }
                    .opacity(blockOpacity)
            }
            .scaleEffect(blockScale)
        }
        .frame(width: 7 * s, height: 5 * s)
    }

    private var block: some View {
        RoundedRectangle(cornerRadius: radius, style: .circular)
            .fill(blockColor)
            .frame(width: 3 * module, height: 5 * module)
    }

    private func bar(_ progress: Double) -> some View {
        RoundedRectangle(cornerRadius: radius, style: .circular)
            .fill(equalsColor)
            .frame(width: 3 * module, height: module)
            .mask(alignment: .leading) {
                Rectangle().frame(width: 3 * module * progress)
            }
    }
}

// MARK: - 1. Logo reveal

public enum RevealTimeline {
    public static let top = (start: 0.0, end: 0.540)
    public static let low = (start: 0.180, end: 0.720)
    public static let land = 0.900
    public static let rest = land + 4 * ECMotion.caret          // 3.02 s

    public struct Frame: Equatable { public var top: Double; public var low: Double; public var block: Bool }

    public static func frame(at t: Double) -> Frame {
        Frame(top: ECMotion.segment(t, top.start, top.end, ECMotion.draw),
              low: ECMotion.segment(t, low.start, low.end, ECMotion.draw),
              block: t >= land && ECMotion.signOffVisible(t, from: land))
    }
}

public struct ECReveal: View {
    public var module: CGFloat
    public var equalsColor: Color
    public var blockColor: Color
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var start = Date.now
    @State private var finished = false

    /// Defaults are the on-Ink brand colours: Paper =, Amber block.
    public init(module: CGFloat = 16, equalsColor: Color = ECColor.paper.color, blockColor: Color = ECColor.amber.color) {
        self.module = module
        self.equalsColor = equalsColor
        self.blockColor = blockColor
    }

    public var body: some View {
        TimelineView(.animation(minimumInterval: nil, paused: finished || reduceMotion)) { context in
            let t = (finished || reduceMotion) ? RevealTimeline.rest : context.date.timeIntervalSince(start)
            let f = RevealTimeline.frame(at: t)
            ECSymbol(module: module, equalsColor: equalsColor, blockColor: blockColor,
                     topBar: f.top, lowBar: f.low, blockOpacity: f.block ? 1 : 0)
        }
        .task {
            start = .now
            try? await Task.sleep(for: .seconds(RevealTimeline.rest))
            finished = true
        }
        .accessibilityElement()
        .accessibilityLabel("EnvCloak")
    }
}

// MARK: - 2. Loaders

/// Hinted sizes. Module s: 2 pt at 16, 3 pt at 24, 6 pt at 48. Fill steps = block height in points.
public enum ECLoaderSize: CGFloat, CaseIterable, Sendable {
    case small = 16, regular = 24, large = 48
    public var module: CGFloat { self == .small ? 2 : self == .regular ? 3 : 6 }
    public var steps: Double { Double(5 * module) }
}

/// Indeterminate: the block blinks like a caret over its ghost.
public struct ECBusy: View {
    public var size: ECLoaderSize
    public var color: Color
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var start = Date.now
    @State private var dimmed = false

    public init(size: ECLoaderSize = .small, color: Color = .primary) {
        self.size = size
        self.color = color
    }

    public var body: some View {
        Group {
            if reduceMotion {
                // No hard flashing: breathe between full and the ghost, 1060 ms each way.
                mark(opacity: dimmed ? 0 : 1)
                    .onAppear {
                        withAnimation(.timingCurve(0.45, 0, 0.55, 1, duration: 2 * ECMotion.caret)
                            .repeatForever(autoreverses: true)) { dimmed = true }
                    }
            } else {
                TimelineView(.periodic(from: start, by: ECMotion.caret)) { context in
                    let beat = Int((context.date.timeIntervalSince(start) / ECMotion.caret).rounded(.down))
                    mark(opacity: beat % 2 == 0 ? 1 : 0)
                }
            }
        }
        .frame(width: size.rawValue, height: size.rawValue)
        .accessibilityElement()
        .accessibilityLabel("Working")
    }

    private func mark(opacity: Double) -> some View {
        ECSymbol(module: size.module, equalsColor: color, blockColor: color, blockOpacity: opacity, showsTrack: true)
    }
}

/// Determinate: the block fills bottom-up in whole-point steps; when full it signs off with two blinks.
public struct ECProgress: View {
    public var progress: Double
    public var size: ECLoaderSize
    public var color: Color
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var completedAt: Date?

    public init(progress: Double, size: ECLoaderSize = .small, color: Color = .primary) {
        self.progress = progress
        self.size = size
        self.color = color
    }

    private var level: Double {
        (min(max(progress, 0), 1) * size.steps).rounded(.down) / size.steps
    }

    public var body: some View {
        TimelineView(.periodic(from: completedAt ?? .now, by: ECMotion.caret)) { context in
            let visible = completedAt.map { ECMotion.signOffVisible(context.date.timeIntervalSince($0), from: 0) } ?? true
            ECSymbol(module: size.module, equalsColor: color, blockColor: color,
                     blockOpacity: visible ? 1 : 0, level: level, showsTrack: true)
        }
        .animation(reduceMotion ? nil : .timingCurve(0.2, 0, 0, 1, duration: 0.24), value: level)
        .onChange(of: level) { _, newValue in
            completedAt = (newValue >= 1 && !reduceMotion) ? .now : nil
        }
        .frame(width: size.rawValue, height: size.rawValue)
        .accessibilityElement()
        .accessibilityLabel("Progress")
        .accessibilityValue("\(Int(level * 100)) percent")
    }
}

// MARK: - 3. Redaction

public enum RedactionTimeline {
    public static let key = Array("OPENAI_API_KEY=")
    public static let value = Array("sk-demo-xxxx")          // a fake demo value; never show a real key shape
    public static let line = key + value
    public static let type0 = 2 * ECMotion.caret              // one caret blink on the empty line first
    public static let perChar = 0.055
    public static let beat = 0.220                            // pause after the =
    public static let cover = 0.240
    public static let collapse = 0.360

    /// When character i appears (seconds).
    public static func typedAt(_ i: Int) -> Double {
        if i < key.count { return type0 + perChar * Double(i) }
        return type0 + perChar * Double(key.count - 1) + beat + perChar * Double(i - key.count)
    }
    public static let typed = typedAt(line.count - 1)          // 2.655
    public static let cover0 = typed + ECMotion.caret          // 3.185
    public static let cover1 = cover0 + cover                  // 3.425
    public static let collapse1 = cover1 + collapse            // 3.785
    public static let rest = collapse1 + 4 * ECMotion.caret    // 5.905

    public struct Frame: Equatable {
        public var typed: Int            // characters shown, from the left
        public var valueHidden: Bool
        public var left: Double          // first cell the block covers (columns, fractional while moving)
        public var right: Double         // last cell the block covers
        public var blockVisible: Bool
    }

    public static func frame(at t: Double) -> Frame {
        let n = line.indices.filter { typedAt($0) <= t }.count
        let first = Double(key.count), last = Double(line.count)
        if t < cover0 {
            let visible = t < ECMotion.caret || t >= type0
            return Frame(typed: n, valueHidden: false, left: Double(n), right: Double(n), blockVisible: visible)
        }
        if t < cover1 {
            let p = ECMotion.segment(t, cover0, cover1, ECMotion.settle)
            return Frame(typed: n, valueHidden: false, left: last - p * (last - first), right: last, blockVisible: true)
        }
        let q = ECMotion.segment(t, cover1, collapse1, ECMotion.settle)
        return Frame(typed: n, valueHidden: true, left: first, right: last - q * (last - first),
                     blockVisible: ECMotion.signOffVisible(t, from: collapse1))
    }
}

/// The hero and onboarding line. Geometry in em: cell 0.65, block 0.5088 x 0.848 on the baseline, radius 0.0424.
public struct ECRedaction: View {
    public var fontSize: CGFloat
    public var textColor: Color
    public var blockColor: Color
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var start = Date.now
    @State private var finished = false

    /// Defaults are the on-Ink colours: Paper text, Amber block. On Paper use Ink for both.
    public init(fontSize: CGFloat = 32, textColor: Color = ECColor.paper.color, blockColor: Color = ECColor.amber.color) {
        self.fontSize = fontSize
        self.textColor = textColor
        self.blockColor = blockColor
    }

    public var body: some View {
        let em = fontSize
        let cell = 0.65 * em
        let font = ECFont.martianMono(size: em)
        TimelineView(.animation(minimumInterval: nil, paused: finished || reduceMotion)) { context in
            let t = (finished || reduceMotion) ? RedactionTimeline.rest : context.date.timeIntervalSince(start)
            let f = RedactionTimeline.frame(at: t)
            Canvas { gc, size in
                let baseline = 1.0 * em
                let bw = 0.5088 * em, bh = 0.848 * em, sb = (cell - bw) / 2
                for (i, ch) in RedactionTimeline.line.enumerated() where i < f.typed {
                    if f.valueHidden && i >= RedactionTimeline.key.count { continue }
                    let text = gc.resolve(Text(String(ch)).font(font).foregroundStyle(textColor))
                    let top = baseline - text.firstBaseline(in: size)
                    gc.draw(text, at: CGPoint(x: CGFloat(i) * cell, y: top), anchor: .topLeading)
                }
                if f.blockVisible {
                    let x0 = CGFloat(f.left) * cell + sb
                    let x1 = CGFloat(f.right) * cell + sb + bw
                    let rect = CGRect(x: x0, y: baseline - bh, width: x1 - x0, height: bh)
                    gc.fill(Path(roundedRect: rect, cornerRadius: 0.0424 * em), with: .color(blockColor))
                }
            }
            .frame(width: CGFloat(RedactionTimeline.line.count + 1) * cell, height: 1.25 * em)
        }
        .task {
            start = .now
            try? await Task.sleep(for: .seconds(RedactionTimeline.rest))
            finished = true
        }
        .accessibilityElement()
        .accessibilityLabel("OPENAI_API_KEY, value hidden")
    }
}

// MARK: - 4. Approval

/// The mark in the approval sheet. While `waiting` is true the block is Amber; it pulses once when the
/// request arrives. Amber only sits on Ink, so the mark always carries its plate.
public struct ECApprovalMark: View {
    public var waiting: Bool
    public var module: CGFloat
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var pulses = 0

    public init(waiting: Bool, module: CGFloat = 8) {
        self.waiting = waiting
        self.module = module
    }

    public var body: some View {
        let dark = scheme == .dark
        let tile = 7 * module / 0.6                      // the mark is 60 % of the plate, as on the app icon
        KeyframeAnimator(initialValue: 1.0, trigger: pulses) { scale in
            ECSymbol(module: module,
                     equalsColor: (dark ? ECColor.darkEquals : ECColor.paper).color,
                     blockColor: (waiting ? ECColor.amber : ECColor.paper).color,
                     blockScale: scale)
        } keyframes: { _ in
            LinearKeyframe(1.1, duration: 0.180, timingCurve: ECMotion.settle)
            LinearKeyframe(1.0, duration: 0.420, timingCurve: ECMotion.breathe)
        }
        // Turn to Amber in 120 ms (linear); release to Paper in 240 ms (settle).
        .animation(waiting ? .linear(duration: 0.120) : .timingCurve(0.2, 0, 0, 1, duration: 0.240), value: waiting)
        .offset(x: -module / 4)                          // optical shift, as on the icon
        .frame(width: tile, height: tile)
        .background((dark ? ECColor.darkTile : ECColor.ink).color,
                    in: RoundedRectangle(cornerRadius: tile * 0.225, style: .continuous))
        .onChange(of: waiting) { _, isWaiting in
            if isWaiting && !reduceMotion { pulses += 1 }
        }
        .accessibilityElement()
        .accessibilityLabel(waiting ? "Waiting for Touch ID" : "EnvCloak")
    }
}

// MARK: - Gallery

/// All four moments on Ink, for a debug window or an Xcode preview.
public struct ECMotionGallery: View {
    @State private var waiting = false
    @State private var progress = 0.0

    public init() {}

    public var body: some View {
        VStack(alignment: .leading, spacing: 32) {
            ECReveal()
            HStack(spacing: 16) {
                ECBusy(size: .small, color: ECColor.paper.color)
                ECBusy(size: .regular, color: ECColor.paper.color)
                ECBusy(size: .large, color: ECColor.paper.color)
                ECProgress(progress: progress, size: .large, color: ECColor.paper.color)
            }
            ECRedaction(fontSize: 28)
            ECApprovalMark(waiting: waiting)
                .onTapGesture { waiting.toggle() }
        }
        .padding(40)
        .background(ECColor.ink.color)
        .task {
            for step in [0.2, 0.3, 0.6, 0.9, 1.0] {
                try? await Task.sleep(for: .milliseconds(600))
                progress = step
            }
        }
    }
}
