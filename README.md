# Plan 5 - Hardening del propio C2

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

## Prototipo verificable

`hardening_scan.py` - escáner genérico con 7 reglas (secretos, claves, bind,
entorno, escape hatches, TLS, dependencias), severidades, resumen y
baseline-type ratchet (nuevos vs. corregidos). No depende de C2-DECT.

```powershell
python -m unittest discover -v
python hardening_scan.py --root fixtures/dirty --json
python hardening_scan.py --root fixtures/dirty --baseline fixtures/baseline.txt --json
```

Targets sintéticos: `fixtures/dirty` (7 reglas disparadas) y `fixtures/clean`
(sin hallazgos). Resultado medido en `results.json`, con hashes de las fixtures.
CI ejecuta los tests en cada push.

## Dimensión ofensiva

El modelo de amenaza del propio C2 se estudia desde la perspectiva del
adversario (ver `c2dect-investigacion/OFENSIVA/01-modelo-de-amenaza.md`): los
cinco vectores de la auditoría y los *escape hatches* de laboratorio definen
la superficie que un atacante intentaría explotar.

## Ámbito

Laboratorio aislado, alcance declarado y RoE firmada. Uso exclusivamente
autorizado. Ver `PLANES_INVESTIGACION_4-7.md` y la auditoría incluida.
