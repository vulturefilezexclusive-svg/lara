import SwiftUI
import UniformTypeIdentifiers
import CryptoKit

private struct ImportedIPAMetadata: Identifiable {
    let id = UUID()
    let fileName: String
    let bundleName: String
    let bundleIdentifier: String
    let version: String
    let build: String
    let executable: String
    let architectures: [String]
    let linkedLibraries: [String]
    let byteCount: Int
    let sha256: String
}

struct IPAInspectorView: View {
    @State private var showingImporter = false
    @State private var metadata: ImportedIPAMetadata?
    @State private var errorMessage: String?
    @State private var isInspecting = false

    var body: some View {
        List {
            Section {
                Button {
                    showingImporter = true
                } label: {
                    Label("Import IPA from Files", systemImage: "doc.badge.plus")
                        .font(.headline)
                }
                .disabled(isInspecting)

                if isInspecting {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Inspecting archive…")
                            .foregroundStyle(.secondary)
                    }
                }
            } footer: {
                Text("Select an IPA you own or are authorized to inspect. Importing does not install, launch, or modify the selected app.")
            }

            if let item = metadata {
                Section("Application") {
                    LabeledContent("Name", value: item.bundleName)
                    LabeledContent("Bundle ID", value: item.bundleIdentifier)
                    LabeledContent("Version", value: item.version)
                    LabeledContent("Build", value: item.build)
                    LabeledContent("Executable", value: item.executable)
                    LabeledContent("Archive size", value: ByteCountFormatter.string(fromByteCount: Int64(item.byteCount), countStyle: .file))
                    LabeledContent("SHA-256", value: item.sha256)
                        .textSelection(.enabled)
                }

                Section("Mach-O") {
                    LabeledContent("Architectures", value: item.architectures.isEmpty ? "Not identified" : item.architectures.joined(separator: ", "))
                    LabeledContent("Linked libraries", value: "\(item.linkedLibraries.count)")
                    ForEach(item.linkedLibraries, id: \.self) { library in
                        Text(library)
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }

                Section {
                    Text(item.fileName)
                        .foregroundStyle(.secondary)
                    Button("Clear inspection", role: .destructive) {
                        metadata = nil
                        errorMessage = nil
                    }
                }
            }

            if let errorMessage {
                Section("Inspection error") {
                    Text(errorMessage)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
            }

            Section("Scope") {
                Label("IPA metadata and binary inspection", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                Label("Installed-app discovery is limited by iOS permissions", systemImage: "info.circle")
                Label("No other app's memory or runtime is accessed", systemImage: "lock.fill")
            }
        }
        .navigationTitle("IPA Inspector")
        .fileImporter(
            isPresented: $showingImporter,
            allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .zip],
            allowsMultipleSelection: false,
            onCompletion: handleImport
        )
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        switch result {
        case .failure(let error):
            errorMessage = error.localizedDescription
        case .success(let urls):
            guard let url = urls.first else { return }
            isInspecting = true
            errorMessage = nil
            metadata = nil
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let result = try inspectIPA(at: url)
                    DispatchQueue.main.async {
                        metadata = result
                        isInspecting = false
                    }
                } catch {
                    DispatchQueue.main.async {
                        errorMessage = error.localizedDescription
                        isInspecting = false
                    }
                }
            }
        }
    }

    private func inspectIPA(at url: URL) throws -> ImportedIPAMetadata {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }

        let values = try url.resourceValues(forKeys: [.fileSizeKey])
        guard let size = values.fileSize, size > 0, size <= 512 * 1024 * 1024 else {
            throw IPAInspectionError.invalidSize
        }

        let archiveData = try Data(contentsOf: url, options: .mappedIfSafe)
        let archive = try ZipArchive(data: archiveData)
        let plistEntries = archive.entries.filter {
            !$0.isDirectory && $0.path.hasPrefix("Payload/") &&
            $0.path.hasSuffix(".app/Info.plist")
        }
        guard plistEntries.count == 1, let plistEntry = plistEntries.first else {
            throw IPAInspectionError.appMetadataNotFound
        }

        let plistData = try archive.extract(plistEntry)
        guard let info = try PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any] else {
            throw IPAInspectionError.invalidInfoPlist
        }

        guard let executable = info["CFBundleExecutable"] as? String,
              !executable.isEmpty,
              !executable.contains("/"),
              !executable.contains("..") else {
            throw IPAInspectionError.invalidExecutable
        }

        let appRoot = String(plistEntry.path.dropLast("Info.plist".count))
        let executablePath = appRoot + executable
        guard let executableEntry = archive[executablePath] else {
            throw IPAInspectionError.executableNotFound
        }
        let executableData = try archive.extract(executableEntry)
        let binaryInfo = inspectMachO(executableData)

        let digest = SHA256.hash(data: archiveData).map { String(format: "%02x", $0) }.joined()
        return ImportedIPAMetadata(
            fileName: url.lastPathComponent,
            bundleName: (info["CFBundleDisplayName"] as? String) ?? (info["CFBundleName"] as? String) ?? executable,
            bundleIdentifier: (info["CFBundleIdentifier"] as? String) ?? "Unknown",
            version: (info["CFBundleShortVersionString"] as? String) ?? "Unknown",
            build: (info["CFBundleVersion"] as? String) ?? "Unknown",
            executable: executable,
            architectures: binaryInfo.architectures,
            linkedLibraries: binaryInfo.libraries,
            byteCount: archiveData.count,
            sha256: digest
        )
    }

    private func inspectMachO(_ data: Data) -> (architectures: [String], libraries: [String]) {
        guard data.count >= 28 else { return ([], []) }
        let magic = data.readUInt32LE(at: 0)
        var slices: [(offset: Int, size: Int, cpu: UInt32, subtype: UInt32)] = []

        if magic == 0xfeedfacf {
            slices.append((0, data.count, data.readUInt32LE(at: 4), data.readUInt32LE(at: 8)))
        } else if magic == 0xcafebabe || magic == 0xbebafeca {
            let bigEndian = magic == 0xcafebabe
            let count = min(Int(data.readUInt32(at: 4, bigEndian: bigEndian)), 32)
            for index in 0..<count {
                let offset = 8 + index * 20
                guard offset + 20 <= data.count else { break }
                let cpu = data.readUInt32(at: offset, bigEndian: bigEndian)
                let subtype = data.readUInt32(at: offset + 4, bigEndian: bigEndian)
                let sliceOffset = Int(data.readUInt32(at: offset + 8, bigEndian: bigEndian))
                let sliceSize = Int(data.readUInt32(at: offset + 12, bigEndian: bigEndian))
                if sliceOffset >= 0, sliceSize > 0, sliceOffset <= data.count, sliceSize <= data.count - sliceOffset {
                    slices.append((sliceOffset, sliceSize, cpu, subtype))
                }
            }
        } else {
            return ([], [])
        }

        var architectures: [String] = []
        var libraries: Set<String> = []
        for slice in slices {
            let arch: String
            if slice.cpu == 0x0100000c {
                arch = (slice.subtype & 0x00ffffff) == 2 ? "arm64e" : "arm64"
            } else if slice.cpu == 0x01000007 {
                arch = "x86_64"
            } else {
                arch = String(format: "cpu-0x%08x", slice.cpu)
            }
            if !architectures.contains(arch) { architectures.append(arch) }

            let base = slice.offset
            guard slice.size >= 32 else { continue }
            let commandCount = min(Int(data.readUInt32LE(at: base + 16)), 4096)
            var cursor = base + 32
            let sliceEnd = base + slice.size
            for _ in 0..<commandCount {
                guard cursor + 8 <= sliceEnd else { break }
                let command = data.readUInt32LE(at: cursor)
                let commandSize = Int(data.readUInt32LE(at: cursor + 4))
                guard commandSize >= 8, cursor + commandSize <= sliceEnd else { break }
                let masked = command & 0x7fffffff
                if masked == 0x0c || masked == 0x18 || masked == 0x1f || masked == 0x80000023 {
                    if commandSize >= 24 {
                        let nameOffset = Int(data.readUInt32LE(at: cursor + 8))
                        let nameStart = cursor + nameOffset
                        if nameOffset >= 8, nameStart < cursor + commandSize {
                            let nameEnd = min(cursor + commandSize, data[nameStart..<(cursor + commandSize)].firstIndex(of: 0) ?? (cursor + commandSize))
                            if nameEnd > nameStart, let name = String(data: data[nameStart..<nameEnd], encoding: .utf8) {
                                libraries.insert(name)
                            }
                        }
                    }
                }
                cursor += commandSize
            }
        }
        return (architectures.sorted(), libraries.sorted())
    }
}

private enum IPAInspectionError: LocalizedError {
    case invalidSize, appMetadataNotFound, invalidInfoPlist, invalidExecutable, executableNotFound

    var errorDescription: String? {
        switch self {
        case .invalidSize: return "The IPA is empty or exceeds the 512 MB inspection limit."
        case .appMetadataNotFound: return "Expected exactly one Payload/*.app/Info.plist entry."
        case .invalidInfoPlist: return "The app Info.plist could not be decoded."
        case .invalidExecutable: return "The app executable name is missing or unsafe."
        case .executableNotFound: return "The executable referenced by Info.plist is missing from the IPA."
        }
    }
}

private extension Data {
    func readUInt32LE(at offset: Int) -> UInt32 {
        readUInt32(at: offset, bigEndian: false)
    }

    func readUInt32(at offset: Int, bigEndian: Bool) -> UInt32 {
        guard offset >= 0, offset + 4 <= count else { return 0 }
        let bytes = self[offset..<(offset + 4)]
        let value = bytes.enumerated().reduce(UInt32(0)) { partial, pair in
            partial | (UInt32(pair.element) << (8 * (bigEndian ? (3 - pair.offset) : pair.offset)))
        }
        return value
    }
}
