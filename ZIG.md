# Ejecutable Zig - `scan_zig`

Escáner de endurecimiento en Zig 0.17.1. Recibe rutas de ficheros y reporta
los hallazgos de las reglas HARD-01/03/05/06/07 implementadas en esta version.

```powershell
zig build
zig build test
.\zig-out\bin\scan_zig.exe fixtures\dirty\main.go fixtures\dirty\config.py fixtures\dirty\client.py fixtures\dirty\requirements.txt
```

Sale con código 1 si hay hallazgos, 0 si no los hay (contrato de CI gate).
