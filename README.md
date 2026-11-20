# Plan 5 — Hardening del propio C2

**Solo información y resultados.** Sin código fuente.

## Hipótesis

Los hallazgos de la auditoría ofensiva son reproducibles como gates automáticos
de CI, de modo que una regresión de seguridad se detecte en el pipeline y no en
una auditoría manual anual.

## Gates definidos

| ID | Comprobación | Estado |
|---|---|---|
| HARD-01 | Sin secretos dev hardcodeados en fuentes Go | PASS |
| HARD-02 | Sin claves privadas versionadas | PASS |
| HARD-03 | Bind por defecto en loopback en ambos servidores | PASS |
| HARD-04 | `C2_FRAME_SECRET` documentado en plantillas de entorno | PASS |

Baseline 0: cualquier regresión pone el CI en rojo. Resultado verificado
localmente: **4/4 gates PASS**, `go vet` limpio, workflow YAML válido.

## Pendiente

- HARD-05: aviso visible en arranque cuando se activa un escape hatch.
- Migrar tests cross-tenant de `ci-interactive.yml` a un job no interactivo.
- SBOM y `govulncheck` en el pipeline.

## Ámbito

Laboratorio aislado, alcance declarado y RoE firmada. Uso exclusivamente
autorizado. Ver `PLANES_INVESTIGACION_4-7.md` y la auditoría incluida.
