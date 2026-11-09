import Foundation
import os
import ShellUI

private let log = Logger(subsystem: "dev.nx2apple.shell", category: "cheats")

/// The cheat files a game can use and the player's switches for them.
///
/// The engine reads `<Documents>/games/<title ID>/cheats/<build ID>.txt` (Atmosphère's format) and remembers which entries
/// are on in `<build ID>.enabled`, one name per line. This type gives the game screen a row per entry, keeps that file in
/// step, and copies the files the app ships for a game into its folder the first time the screen opens.
///
/// Everything here is plain file work: the shell never talks to the engine's cheat VM, so a switch takes effect the next
/// time the game starts. The engine applies the enabled entries once per presented frame, and a `- off` half restores a
/// code hook when its switch is turned off, so turning cheats off and restarting is always safe.
public enum GameCheats {
    /// Prefix of the setting ids the cheats panel hands to `ShellActions.onChange`.
    public static let rowPrefix = "cheat."

    /// One `[Name]` or `{Name}` entry of a cheat file.
    struct Entry {
        /// The header name exactly as it is written in the file.
        var name: String
        /// The key `<build>.enabled` uses: the name, or `Name #2`, `Name #3` for a repeated name.
        var key: String
        /// `{Name}`: always on, applied first, not a switch.
        var master: Bool
        /// The name without a trailing `- on` / `- off`, so a pair shows as one switch.
        var label: String
        /// Which half of an on/off pair this is, nil for a plain entry.
        var half: Bool?
        /// Only a plain entry or the `on` half is a row; an `off` half is the restore the engine runs by itself.
        var shown: Bool
    }

    /// One cheat file and its entries.
    struct File {
        var stem: String
        var entries: [Entry]
    }

    // MARK: - Files

    /// The game's cheats folder, the one the engine is pointed at with `DM_CHEATS`.
    public static func folder(for appFolder: URL) -> URL {
        appFolder.appendingPathComponent("cheats", isDirectory: true)
    }

    /// Copies the cheat files the app ships for `gameID` into the game's folder. An existing file is never overwritten, so
    /// a file the player updated stays. Missing folders are created.
    public static func install(gameID: String, appFolder: URL, bundle: Bundle? = nil) {
        let fm = FileManager.default
        let dest = folder(for: appFolder)
        let shipped = shippedFiles(gameID: gameID, bundle: bundle ?? .module)
        guard !shipped.isEmpty else { return }
        do {
            try fm.createDirectory(at: dest, withIntermediateDirectories: true)
        } catch {
            log.error("cannot create \(dest.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return
        }
        for src in shipped {
            let target = dest.appendingPathComponent(src.lastPathComponent)
            guard !fm.fileExists(atPath: target.path) else { continue }
            do {
                try fm.copyItem(at: src, to: target)
                log.info("installed \(src.lastPathComponent, privacy: .public) for \(gameID, privacy: .public)")
            } catch {
                log.error("cannot install \(src.lastPathComponent, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// The game's cheat files, parsed. Empty when the folder has none.
    static func files(appFolder: URL) -> [File] {
        let dir = folder(for: appFolder)
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        return names
            .filter { $0.lowercased().hasSuffix(".txt") && !$0.hasPrefix(".") }
            .sorted()
            .compactMap { name in
                let url = dir.appendingPathComponent(name)
                guard let text = readText(url) else {
                    log.error("cannot read \(url.path, privacy: .public)")
                    return nil
                }
                let entries = parse(text)
                guard !entries.isEmpty else { return nil }
                return File(stem: url.deletingPathExtension().lastPathComponent, entries: entries)
            }
    }

    /// The enabled names of a file's `<stem>.enabled`, or an empty set.
    static func enabledNames(stem: String, appFolder: URL) -> Set<String> {
        let url = folder(for: appFolder).appendingPathComponent(stem + ".enabled")
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return Set(text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty })
    }

    /// Writes the enabled names of one file, the whole file at once: the engine rewrites it the same way from its menu.
    static func save(names: Set<String>, stem: String, appFolder: URL) {
        let url = folder(for: appFolder).appendingPathComponent(stem + ".enabled")
        let text = names.sorted().map { $0 + "\n" }.joined()
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try text.write(to: url, atomically: true, encoding: .utf8)
            log.info("wrote \(names.count, privacy: .public) switch(es) to \(url.lastPathComponent, privacy: .public)")
        } catch {
            log.error("cannot write \(url.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - Panel

    /// The cheats groups of one game: a row per entry, masters left out (they always run) and off halves left out (the
    /// engine runs them when the switch turns off).
    public static func sections(gameID: String, appFolder: URL, bundle: Bundle? = nil) -> [SettingSection] {
        install(gameID: gameID, appFolder: appFolder, bundle: bundle)
        var sections: [SettingSection] = []
        for file in files(appFolder: appFolder) {
            let on = enabledNames(stem: file.stem, appFolder: appFolder)
            var rows: [SettingRow] = []
            for (index, entry) in file.entries.enumerated() where entry.shown && !entry.master {
                let id = "\(rowPrefix)\(file.stem)#\(index)"
                rows.append(SettingRow(id: id, label: entry.label, kind: .toggle(on: "1", off: "0"),
                                       value: on.contains(entry.key) ? "1" : "0"))
            }
            guard !rows.isEmpty else { continue }
            sections.append(SettingSection(id: "cheats.\(file.stem)", title: "Cheats", rows: rows))
        }
        return sections
    }

    /// Turns one row on or off and returns its new value ("1" / "0"). The row id is what `ShellActions.onChange` carries:
    /// `cheat.<file stem>#<entry index>`, an index into the file's parsed entries.
    @discardableResult
    public static func toggle(rowID: String, appFolder: URL) -> String? {
        guard rowID.hasPrefix(rowPrefix) else { return nil }
        let body = rowID.dropFirst(rowPrefix.count)
        guard let hash = body.lastIndex(of: "#") else { return nil }
        let stem = String(body[body.startIndex..<hash])
        guard let index = Int(body[body.index(after: hash)...]) else { return nil }
        let dir = folder(for: appFolder)
        let url = dir.appendingPathComponent(stem + ".txt")
        guard let text = readText(url) else { return nil }
        let entries = parse(text)
        guard entries.indices.contains(index) else { return nil }
        let key = entries[index].key
        var names = enabledNames(stem: stem, appFolder: appFolder)
        let value = names.contains(key) ? "0" : "1"
        if value == "1" {
            names.insert(key)
        } else {
            names.remove(key)
        }
        save(names: names, stem: stem, appFolder: appFolder)
        log.info("switch \(key, privacy: .public) of \(stem, privacy: .public) is now \(value, privacy: .public)")
        return value
    }

    // MARK: - Parsing

    /// The `[Name]` / `{Name}` entries of a cheat file. A header with no code words under it is a credits line or a
    /// section marker, as the engine treats it, and never becomes a row.
    static func parse(_ text: String) -> [Entry] {
        var entries: [Entry] = []
        var current: (name: String, master: Bool, code: Int)?
        var seen: [String: Int] = [:]

        func flush() {
            guard let c = current else { return }
            current = nil
            guard c.code > 0 else { return }
            let (label, half) = splitHalf(c.name)
            let dup = seen[c.name, default: 0]
            seen[c.name] = dup + 1
            let key = dup == 0 ? c.name : "\(c.name) #\(dup + 1)"
            entries.append(Entry(name: c.name, key: key, master: c.master, label: label, half: half, shown: half != true))
        }

        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if let (name, master) = header(line) {
                flush()
                current = (name: name, master: master, code: 0)
                continue
            }
            if current != nil { current!.code += 1 }
        }
        flush()
        return entries
    }

    /// The name of a `[...]` or `{...}` header line, and whether it is a master (`{...}`).
    private static func header(_ line: String) -> (String, Bool)? {
        if line.count > 2, line.hasPrefix("["), line.hasSuffix("]") {
            return (String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces), false)
        }
        if line.count > 2, line.hasPrefix("{"), line.hasSuffix("}") {
            return (String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces), true)
        }
        return nil
    }

    /// Splits a `Name - on` / `Name - off` name into its base and half, mirroring the engine's `onoff_split`.
    static func splitHalf(_ name: String) -> (String, Bool?) {
        var body = name
        var half: Bool?
        let lower = body.lowercased()
        if lower.hasSuffix("off"), body.count >= 4 {
            half = true
            body = String(body.dropLast(3))
        } else if lower.hasSuffix("on"), body.count >= 3 {
            half = false
            body = String(body.dropLast(2))
        } else {
            return (name, nil)
        }
        body = body.trimmingCharacters(in: .whitespaces)
        // The separator the engine accepts between the base and the half: a space, then any of - : _ ( [
        guard let last = body.last, " -:_([".contains(last) else { return (name, nil) }
        let base = String(body.dropLast()).trimmingCharacters(in: .whitespaces)
        guard !base.isEmpty else { return (name, nil) }
        return (base, half)
    }

    // MARK: - Bundled files

    /// The `.txt` files the app ships for `gameID`, from `ShellHost`'s resource bundle.
    private static func shippedFiles(gameID: String, bundle: Bundle) -> [URL] {
        guard let root = bundle.resourceURL else { return [] }
        let dir = root.appendingPathComponent("cheats", isDirectory: true).appendingPathComponent(gameID, isDirectory: true)
        let names = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        let found = names.filter { $0.pathExtension.lowercased() == "txt" }
        if !found.isEmpty { return found }
        // A resource rule that flattened the folder leaves the files at the bundle root: take only 16-hex-digit stems.
        let flat = (try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? []
        return flat.filter { url in
            guard url.pathExtension.lowercased() == "txt" else { return false }
            let stem = url.deletingPathExtension().lastPathComponent
            return stem.count == 16 && stem.allSatisfy(\.isHexDigit)
        }
    }

    /// A cheat file as text: UTF-8, then Latin-1, then GB18030 for the Chinese site files.
    private static func readText(_ url: URL) -> String? {
        if let s = try? String(contentsOf: url, encoding: .utf8) { return s }
        if let s = try? String(contentsOf: url, encoding: .isoLatin1) { return s }
        let gb = String.Encoding(rawValue: CFStringConvertEncodingToNSStringEncoding(CFStringEncoding(CFStringEncodings.GB_18030_2000.rawValue)))
        return try? String(contentsOf: url, encoding: gb)
    }
}
