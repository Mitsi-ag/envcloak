import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct BindingSelection: Identifiable {
    let id = UUID()
    var project: DaemonText?
    var key: ItemView?
    var variable: String = ""
    var profile: String = ""
}

struct BindingSheet: View {
    let session: VaultSession
    let selection: BindingSelection
    @Environment(\.dismiss) private var dismiss
    @Environment(\.undoManager) private var undoManager
    @State private var project: DaemonText?
    @State private var profile = ""
    @State private var variable = ""
    @State private var slug = ""
    @State private var field = ""
    @State private var query = ""
    @State private var busy = false
    private var keys: [ItemView] {
        session.items.rows.filter { item in
            item.class == .secret && (query.isEmpty || [item.slug.escaped, item.provider?.escaped ?? "", item.account?.email?.escaped ?? "", item.classification.rawValue].joined(separator: " ").localizedCaseInsensitiveContains(query))
        }.sorted { left, right in
            if (left.classification == .test) != (right.classification == .test) { return left.classification == .test }
            return left.slug.escaped < right.slug.escaped
        }
    }
    private var key: ItemView? { keys.first { $0.slug.escaped == slug } }
    private var edit: BindingEdit? {
        guard let project, key != nil else { return nil }
        let previous = session.projects.opened?.directory == project
            ? session.projects.opened?.bindings(profile: profile.isEmpty ? nil : profile).first { $0.env_name?.escaped == variable }?.reference : nil
        return BindingEdit(project: project, profile: profile.isEmpty ? nil : profile, envName: variable,
                           reference: slug + (field.isEmpty ? "" : "#" + field), previous: previous)
    }
    private func keyLabel(_ item: ItemView) -> String {
        let account = item.account?.email?.escaped ?? "No account"
        return "\(item.slug.escaped) · \(item.classification.rawValue.capitalized) · \(account)"
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Use in project").font(.title2)
            Picker("Project", selection: $project) {
                Text("Choose a project").tag(Optional<DaemonText>.none)
                ForEach(session.projects.directories, id: \.self) { dir in Text(session.projects.title(dir)).tag(Optional(dir)) }
            }.accessibilityIdentifier("binding.project")
            HStack {
                Picker("Profile", selection: $profile) {
                    Text("Default").tag("")
                    ForEach(session.projects.opened?.profiles ?? [], id: \.self) { Text($0).tag($0) }
                    if !profile.isEmpty, !(session.projects.opened?.profiles ?? []).contains(profile) { Text(Escape.display(profile)).tag(profile) }
                }
                TextField("New profile (optional)", text: $profile).accessibilityIdentifier("binding.profile")
            }
            TextField("Variable", text: $variable).font(ECFont.martianMono(size: 12)).accessibilityIdentifier("binding.variable")
            TextField("Search keys, providers, accounts or class", text: $query)
            Picker("Key", selection: $slug) {
                Text("Choose a key").tag("")
                ForEach(keys, id: \.id) { item in
                    Text(keyLabel(item)).tag(item.slug.escaped)
                }
            }.accessibilityIdentifier("binding.key")
            if let key, key.fields.count > 1 {
                Picker("Field", selection: $field) {
                    Text("Choose a field").tag("")
                    ForEach(key.fields, id: \.name) { Text($0.name.escaped).tag($0.name.escaped) }
                }
            }
            if let edit {
                Text(edit.preview).font(ECFont.martianMono(size: 12)).padding(10).frame(maxWidth: .infinity, alignment: .leading).background(ECToken.raised.color)
                if let previous = edit.previous { Text("Replaces " + previous.escaped) }
            }
            Text("This edits envcloak.toml. It is not an approval: the next run still asks.").foregroundStyle(ECToken.secondary.color)
            HStack {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("Add to envcloak.toml") {
                    guard let edit else { return }
                    busy = true
                    Task {
                        let saved = await session.bindings.apply(edit, session: session, manager: undoManager)
                        busy = false
                        if saved { dismiss() }
                    }
                }.keyboardShortcut(.return, modifiers: .command).accessibilityIdentifier("binding.save")
                    .disabled(busy || edit?.cliArguments == nil || session.state != .ready || ((key?.fields.count ?? 0) > 1 && field.isEmpty))
            }
        }.padding(24).frame(width: 520).interactiveDismissDisabled(busy)
        .task {
            project = selection.project ?? session.projects.directories.first
            profile = selection.profile; variable = selection.variable
            slug = selection.key?.slug.escaped ?? ""
            if variable.isEmpty { variable = selection.key?.env_hint?.escaped ?? "" }
        }
        .task(id: project) { if let project { await session.openProject(project) } }
        .onChange(of: slug) { _, _ in field = ""; if variable.isEmpty { variable = key?.env_hint?.escaped ?? "" } }
        .onChange(of: session.state) { _, state in if state != .ready { dismiss() } }
    }
}
