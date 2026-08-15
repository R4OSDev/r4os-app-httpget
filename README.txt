HTTPGET.R4X
===========

HTTPGET.R4X ist das Terminalwerkzeug fuer einfache HTTP-GET-Abfragen ueber
den R4NET-/TCP-Servicepfad.

Projektstruktur seit 0.51.19:
- `build.zig` baut die App als eigenes SDK-Projekt.
- `build.zig.zon` bindet `r4os_sdk` als Paket.
- `module.R4MF` beschreibt Artefakt, Zielpfad, Imports und Contract.

Build:

    cd Code\System\Software\HttpGet
    ..\..\..\DevTools\Zig\zig.exe build

Ergebnis:

    Code\System\Software\HttpGet\zig-out\HTTPGET.R4X

Contract:
- R4XStart-Entry: `httpget_main`
- App-Klasse: `console`
- R4L-Imports: `R4SYS`, `R4NET`
- Zielpfad im Image: `C:\R4OS\SOFTWARE\TERMINAL\HTTPGET.R4X`

