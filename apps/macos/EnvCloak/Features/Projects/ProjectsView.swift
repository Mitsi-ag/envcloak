import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct ProjectsOverview: View {
    let session: VaultSession
    @Binding var route: Route?
    var body: some View {
        if session.projects.failure != nil {
            ContentUnavailableView("Projects could not be refreshed", systemImage: "exclamationmark.triangle", description: Text("Try again. No partial listing is shown."))
        } else if session.projects.directories.isEmpty {
            VStack {
                ContentUnavailableView("No projects yet.", systemImage: "folder", description: Text("Run envcloak init in a repo, or add a folder that has an envcloak.toml."))
                Button("Add project folder…") { WorkspaceActions.addFolder(session) { route = .project($0) } }
                Button("Copy envcloak init") { WorkspaceActions.copy("envcloak init") }
            }
        } else {
            List(session.projects.directories, id: \.self) { directory in
                Button { route = .project(directory) } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "folder").foregroundStyle(ECToken.secondary.color)
                        VStack(alignment: .leading) {
                            Text(MetadataRequest.basename(directory)).font(.headline)
                            Text(directory.escaped).font(ECFont.martianMono(size: 10)).lineLimit(1).truncationMode(.middle).help(directory.escaped)
                        }
                        Spacer()
                        if let row = session.projects.rows.first(where: { $0.dir == directory }) {
                            Text("\(row.bindings.count) adopted bindings").foregroundStyle(ECToken.secondary.color)
                        } else { Text("Not checked") }
                    }.frame(minHeight: 48).contentShape(Rectangle())
                }.buttonStyle(.plain).accessibilityIdentifier("project.open." + directory.escaped)
            }.accessibilityIdentifier("projects.list")
        }
    }
}

struct ProjectDetail: View {
    let session: VaultSession
    let directory: DaemonText
    @Binding var selectedKey: DaemonText?
    @State private var profile = ""
    private var opened: OpenedProject? {
        guard let project = session.projects.opened, project.directory == directory else { return nil }
        return project
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(opened?.title ?? MetadataRequest.basename(directory)).font(.title2).accessibilityIdentifier("project.title")
            Text(directory.escaped).font(ECFont.martianMono(size: 12)).textSelection(.enabled)
            HStack {
                Button("Show in Finder") { WorkspaceActions.showFolder(directory) }
                Button("Open in Terminal") { WorkspaceActions.openFolderInTerminal(directory); session.notice = "Folder command copied. Paste it in Terminal." }
                Button("Copy path") { WorkspaceActions.copy(MetadataRequest.path(directory)) }
            }
            if session.projects.openedDirectory != directory {
                Text("Not checked").foregroundStyle(ECToken.secondary.color); Spacer()
            } else if session.projects.manifestMissing {
                ContentUnavailableView("This folder has no envcloak.toml.", systemImage: "folder", description: Text("Run envcloak init there to import its .env files and create one."))
                Button("Copy envcloak init") { WorkspaceActions.copy("envcloak init") }
            } else if let failure = session.projects.checkFailure {
                ContentUnavailableView("envcloak.toml could not be read", systemImage: "exclamationmark.triangle", description: Text(failure.description + ". Run envcloak check in this folder."))
                Button("Check again") { Task { await session.openProject(directory) } }
            } else if let project = opened {
                Picker("Profile", selection: $profile) {
                    Text("Default").tag("")
                    ForEach(project.profiles, id: \.self) { Text($0).tag($0) }
                }.pickerStyle(.segmented)
                BindingsTable(session: session, project: project, profile: profile.isEmpty ? nil : profile, selectedKey: $selectedKey)
                Text("Grants in force in this project").font(.headline)
                GrantRows(session: session, directory: directory, slug: nil)
            } else { Text("Not checked").foregroundStyle(ECToken.secondary.color); Spacer() }
        }.padding(16)
        .task(id: directory) { profile = ""; await session.openProject(directory) }
        .onChange(of: session.projects.opened?.profiles) { _, profiles in
            if !profile.isEmpty, !(profiles ?? []).contains(profile) { profile = "" }
        }
    }
}

extension RefStatus {
    var words: String {
        switch self {
        case .ok: "Resolves"
        case .unknownItem: "No key with this name"
        case .unknownField: "That key has no such field"
        case .ambiguousField: "Choose a field"
        case .noField: "This key has no field"
        case .cardReference: "Cards cannot be bound"
        case .issuerCredentialReference: "Issuer credentials cannot be bound"
        case .unknownItemClass: "Unsupported key class"
        case .loginReference: "Sign-in fields cannot be bound"
        case .invalidReference: "Invalid reference"
        case .looksLikeValue: "Not shown: looks like a key or token"
        case .unchecked: "Not checked"
        }
    }
}
