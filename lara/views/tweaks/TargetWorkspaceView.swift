import SwiftUI
import UniformTypeIdentifiers

/// A local workspace for organizing IPA files the user explicitly selects.
/// This view does not install, launch, inspect runtime state, or modify other apps.
private struct TargetWorkspaceItem: Codable, Identifiable, Hashable {
    let id: UUID
    let fileName: String
    let byteCount: Int
    let importedAt: Date

    init(fileName: String, byteCount: Int) {
        self.id = UUID()
        self.fileName = fileName
        self.byteCount = byteCount
        self.importedAt = Date()
    }
}

struct TargetWorkspaceView: View {
    @AppStorage("lara.targetWorkspace.items") private var savedItems = "[]"
    @AppStorage("lara.targetWorkspace.selectedID") private var selectedID = ""
    @State private var items: [TargetWorkspaceItem] = []
    @State private var showingImporter = false
    @State private var showingMenuPreview = false
    @State private var showingInspector = false
    @State private var errorMessage: String?

    private var selectedItem: TargetWorkspaceItem? {
        items.first { $0.id.uuidString == selectedID }
    }

    var body: some View {
        List {
            Section {
                Button {
                    showingImporter = true
                } label: {
                    Label("Import IPA files", systemImage: "doc.badge.plus")
                }

                if let selectedItem {
                    LabeledContent("Selected", value: selectedItem.fileName)
                    Label("Imported for static review", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } else {
                    Text("Import an IPA and select it as the current analysis target.")
                        .foregroundStyle(.secondary)
                }
            } footer: {
                Text("This workspace tracks files selected by you. It does not discover every installed app or interact with another app's running process.")
            }

            if !items.isEmpty {
                Section("Workspace") {
                    ForEach(items) { item in
                        Button {
                            selectedID = item.id.uuidString
                        } label: {
                            HStack(spacing: 12) {
                                Image(systemName: "app.dashed")
                                    .font(.title2)
                                    .foregroundStyle(.secondary)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(item.fileName)
                                        .foregroundStyle(.primary)
                                        .lineLimit(1)
                                    Text(ByteCountFormatter.string(fromByteCount: Int64(item.byteCount), countStyle: .file))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if selectedID == item.id.uuidString {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundStyle(.green)
                                }
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .swipeActions {
                            Button("Remove", role: .destructive) {
                                remove(item)
                            }
                        }
                    }
                }
            }

            Section("Floating menu preview") {
                Toggle("Show in-app menu preview", isOn: $showingMenuPreview)
                Text("Preview controls are confined to this Lara screen; they do not appear over other apps.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Section("Runtime status") {
                LabeledContent("Workspace", value: "Ready")
                LabeledContent("Target process", value: "Not attached")
                LabeledContent("ESP / aim features", value: "Not available")
            }

            if let errorMessage {
                Section("Import error") {
                    Text(errorMessage)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
            }
        }
        .navigationTitle("Target Workspace")
        .navigationDestination(isPresented: $showingInspector) {
            IPAInspectorView()
        }
        .overlay(alignment: .bottomTrailing) {
            if showingMenuPreview {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Lara Tools")
                            .font(.headline)
                        Spacer()
                        Button {
                            showingMenuPreview = false
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                        }
                    }
                    Divider()
                    Label("Selected IPA", systemImage: "app")
                    Text(selectedItem?.fileName ?? "No target selected")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        Button("Open IPA Inspector") {
                            // The inspector remains a separate, user-initiated static analysis screen.
                            showingInspector = true
                        }
                        .buttonStyle(.borderedProminent)
                }
                .padding()
                .frame(maxWidth: 260)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18))
                .overlay(RoundedRectangle(cornerRadius: 18).stroke(.white.opacity(0.15)))
                .shadow(radius: 12)
                .padding()
            }
        }
        .fileImporter(
            isPresented: $showingImporter,
            allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .zip],
            allowsMultipleSelection: true,
            onCompletion: handleImport
        )
        .onAppear(perform: loadItems)
    }

    private func loadItems() {
        guard let data = savedItems.data(using: .utf8),
              let decoded = try? JSONDecoder().decode([TargetWorkspaceItem].self, from: data) else {
            items = []
            return
        }
        items = decoded
    }

    private func persistItems() {
        guard let data = try? JSONEncoder().encode(items),
              let value = String(data: data, encoding: .utf8) else { return }
        savedItems = value
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        switch result {
        case .failure(let error):
            errorMessage = error.localizedDescription
        case .success(let urls):
            errorMessage = nil
            for url in urls {
                let accessed = url.startAccessingSecurityScopedResource()
                defer { if accessed { url.stopAccessingSecurityScopedResource() } }
                let byteCount = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                guard !items.contains(where: { $0.fileName == url.lastPathComponent }) else { continue }
                items.append(TargetWorkspaceItem(fileName: url.lastPathComponent, byteCount: byteCount))
            }
            persistItems()
        }
    }

    private func remove(_ item: TargetWorkspaceItem) {
        items.removeAll { $0.id == item.id }
        if selectedID == item.id.uuidString { selectedID = "" }
        persistItems()
    }
}

