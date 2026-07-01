# A03:2025 — Software Supply Chain Failures

## Was ist die Schwachstelle?
Eine veraltete Transitiv-/Direkt-Dependency mit bekannter CVE (z. B.
commons-collections 3.2.1 → CVE-2015-7501, Deserialization-RCE) gelangt
ungeprüft in den Build.

## Wie wurde sie demonstriert?
Vulnerable Dependency in `pom.xml` aktivieren →
`mvn org.owasp:dependency-check-maven:check` →
`target/dependency-check-report.html` listet die CVE mit CVSS-Score.

## Welche Gegenmassnahme wurde implementiert?
- OWASP Dependency-Check Maven-Plugin mit `failBuildOnCVSS=7`.
- Verankerung in der CI (`.gitlab-ci.yml`), sodass jeder Push gescannt wird.
- Prozess: Dependency aktualisieren/entfernen, sauberen Report als Nachweis ablegen.

> Build-zeitlicher Fix — bewusst NICHT im Request-Pfad. Das ist der Lerneffekt.
