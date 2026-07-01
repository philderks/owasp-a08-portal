# A08:2025 — Software or Data Integrity Failures

## Was ist die Schwachstelle?

Ein Datei-Upload-Portal nimmt Dateien an und gibt sie später wieder aus, ohne
zu prüfen, ob (a) der Inhalt dem entspricht, was der Client behauptet, und
(b) die gespeicherte Datei zwischen Upload und Download unverändert geblieben
ist. Folgen:

- Eine getarnte ausführbare Datei (`malware.exe` → `bild.png`) wird akzeptiert.
- Eine am Speicher manipulierte Datei wird unbemerkt ausgeliefert.
- Es gibt keinen Integritäts-Anker, an dem eine Manipulation auffallen würde.

*(OWASP A08 umfasst auch Insecure Deserialization. Das ist hier bewusst nicht
der Kern — siehe Scope unten.)*

## Wie wurde sie demonstriert?

1. Upload eines gültigen Bildes → Eintrag mit SHA-256 erscheint.
2. App stoppen, Blob unter `./data/uploads/<uuid>` um ein Byte ändern.
3. Download anstoßen → ohne Schutz würde die manipulierte Datei rausgehen.
4. Zusätzlich: `.exe` als `.png` umbenennen und hochladen.

*(Screenshots: Upload-Liste mit Hash, Log-Zeile `INTEGRITY_VIOLATION`,
abgelehnter Executable-Upload.)*

## Welche Gegenmassnahme wurde implementiert?

`file/FileService.java`:

- **SHA-256 bei Upload** berechnet und in `FileEntity.sha256` gespeichert
  (nur Metadaten in der DB, Blob auf Disk).
- **Re-Hash bei jedem Download** und Vergleich → bei Abweichung
  `IntegrityException` + Log-Event `INTEGRITY_VIOLATION`.
- **Content-basierte Typprüfung** mit Apache Tika (`tika.detect(bytes)`) gegen
  eine MIME-Allowlist — der Client-`Content-Type`-Header wird ignoriert.
- **Deny-List für Executables** (`.exe`, `.sh`, `.jar`, …) als zweite Barriere.
- **Kein Path-Traversal**: Speicherung unter zufälligem UUID-Namen, Pfad
  normalisiert und gegen das Storage-Verzeichnis geprüft.

## Scope / Abgrenzung

Insecure Deserialization (zweites Gesicht von A08) ist als optionale Kür
vorgesehen: ein Import einer serialisierten „Projekt-Config" würde RCE über
ein manipuliertes Objekt zeigen; Gegenmassnahme wäre ein Allowlist-basierter
`ObjectInputFilter` bzw. ein Format ohne Code-Ausführung (JSON statt Java-Serialisierung).
