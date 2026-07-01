# A01:2025 — Broken Access Control

## Was ist die Schwachstelle?
IDOR: Endpunkte wie `/files/{id}/download` referenzieren Objekte direkt über die
ID. Ohne Ownership-Prüfung kann ein angemeldeter User durch Hochzählen der ID
fremde Dateien herunterladen.

## Wie wurde sie demonstriert?
Als `user` eine Datei hochladen, `id` notieren, dann eine fremde `id` in der URL
aufrufen → ohne Schutz erfolgt der Download.

## Welche Gegenmassnahme wurde implementiert?
- Programmatischer Ownership-Check in `FileService.load(id, requester, isAdmin)`:
  Zugriff nur, wenn `owner == requester` oder Rolle ADMIN → sonst
  `AccessDeniedException` (403) + Log-Event `ACCESS_DENIED`.
- Method-Level Security mit `@PreAuthorize("hasRole('ADMIN')")` auf
  `/admin/files` (Defence in Depth zusätzlich zur URL-Regel in `SecurityConfig`).
- Least Privilege global: `anyRequest().authenticated()`.
