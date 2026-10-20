import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct CommandPalette: View {
    let session: VaultSession
    let selectedKey: ItemView?
    let onEffect: (PaletteEffect) -> Void
    let onClose: () -> Void

    @State private var query = ""
    @State private var highlightedId: String?
    @FocusState private var searchFocused: Bool
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private var projectTitles: [DaemonText: String] {
        var map: [DaemonText: String] = [:]
        for dir in session.projects.directories {
            map[dir] = session.projects.title(dir)
        }
        return map
    }

    private var filteredItems: [PaletteItem] {
        PaletteBuilder.items(
            query: query,
            selectedKey: selectedKey,
            projects: session.projects.directories,
            projectTitles: projectTitles,
            keys: session.items.rows,
            grants: session.grants.rows.filter { session.grants.remaining($0) > 0 },
            pendingCount: Int(session.pendingCount) + Int(session.appRequestsCount)
        )
    }

    private var sections: [(String, [PaletteItem])] {
        var order: [String] = []
        var grouped: [String: [PaletteItem]] = [:]
        for item in filteredItems {
            if grouped[item.section] == nil {
                order.append(item.section)
                grouped[item.section] = []
            }
            grouped[item.section]?.append(item)
        }
        return order.map { ($0, grouped[$0] ?? []) }
    }

    private var activeItem: PaletteItem? {
        if let highlightedId, let found = filteredItems.first(where: { $0.id == highlightedId }) {
            return found
        }
        return filteredItems.first
    }

    var body: some View {
        paletteContainer
            .frame(width: 560)
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("palette.container")
            .onAppear {
                searchFocused = true
                highlightedId = filteredItems.first?.id
            }
            .onChange(of: query) { _, _ in
                highlightedId = filteredItems.first?.id
            }
            .onExitCommand {
                onClose()
            }
            .onMoveCommand { direction in
                switch direction {
                case .down: moveHighlight(delta: 1)
                case .up: moveHighlight(delta: -1)
                default: break
                }
            }
            .onKeyPress(keys: [.return], phases: .down) { press in
                guard let current = activeItem else { return .ignored }
                if press.modifiers.contains(.command), let secondary = current.secondaryEffect {
                    onEffect(secondary)
                } else if press.modifiers.contains(.option), let option = current.optionEffect {
                    onEffect(option)
                } else {
                    onEffect(current.primaryEffect)
                }
                onClose()
                return .handled
            }
    }

    @ViewBuilder
    private var paletteContainer: some View {
        if reduceTransparency {
            paletteContent
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(ECToken.raised.color)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .stroke(ECToken.rule.color, lineWidth: 1)
                        )
                )
        } else {
            GlassEffectContainer {
                paletteContent
                    .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            }
        }
    }

    private var paletteContent: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityHidden(true)
                TextField("Type a command or search (p projects, k keys, a agents, > commands)", text: $query)
                    .textFieldStyle(.plain)
                    .focused($searchFocused)
                    .onSubmit {
                        if let current = activeItem {
                            onEffect(current.primaryEffect)
                            onClose()
                        }
                    }
                    .accessibilityIdentifier("palette.search")
                Button("Close") {
                    onClose()
                }
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("palette.close")
            }
            .padding(12)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    if sections.isEmpty {
                        Text("No matching items")
                            .foregroundStyle(ECToken.secondary.color)
                            .padding(12)
                            .accessibilityIdentifier("palette.empty")
                    } else {
                        ForEach(sections, id: \.0) { sectionTitle, items in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(sectionTitle)
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(ECToken.secondary.color)
                                    .padding(.horizontal, 12)
                                ForEach(items) { item in
                                    paletteRow(item)
                                }
                            }
                        }
                    }
                }
                .padding(.vertical, 8)
            }
            .frame(maxHeight: 340)
        }
    }

    private func paletteRow(_ item: PaletteItem) -> some View {
        let isHighlighted = activeItem?.id == item.id
        return Button {
            onEffect(item.primaryEffect)
            onClose()
        } label: {
            HStack(spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title)
                        .font(.body)
                        .foregroundStyle(ECToken.text.color)
                    if let subtitle = item.subtitle, !subtitle.isEmpty {
                        Text(subtitle)
                            .font(ECFont.martianMono(size: 11))
                            .foregroundStyle(ECToken.secondary.color)
                    }
                }
                Spacer()
                if let shortcut = item.shortcut {
                    Text(shortcut)
                        .font(ECFont.martianMono(size: 11))
                        .foregroundStyle(ECToken.secondary.color)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(isHighlighted ? ECToken.raised.color : Color.clear)
            )
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("palette.item." + item.id)
    }

    private func moveHighlight(delta: Int) {
        let all = filteredItems
        guard !all.isEmpty else { return }
        guard let currentId = activeItem?.id, let idx = all.firstIndex(where: { $0.id == currentId }) else {
            highlightedId = all.first?.id
            return
        }
        let next = max(0, min(all.count - 1, idx + delta))
        highlightedId = all[next].id
    }
}
