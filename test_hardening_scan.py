"""Tests del escaneo de endurecimiento (targets sinteticos)."""

import unittest
from pathlib import Path

from hardening_scan import diff_baseline, load_baseline, make_baseline, scan, summarize

HERE = Path(__file__).resolve().parent
DIRTY = HERE / "fixtures" / "dirty"
CLEAN = HERE / "fixtures" / "clean"


class TestScan(unittest.TestCase):
    def test_target_sucio_detecta_siete_reglas(self):
        findings = scan(DIRTY)
        rules = {f["rule"] for f in findings}
        self.assertEqual(
            rules,
            {"HARD-01", "HARD-02", "HARD-03", "HARD-04", "HARD-05", "HARD-06", "HARD-07"},
        )

    def test_target_limpio_sin_hallazgos(self):
        self.assertEqual(scan(CLEAN), [])

    def test_severidades_asignadas(self):
        findings = scan(DIRTY)
        severities = {f["rule"]: f["severity"] for f in findings}
        self.assertEqual(severities["HARD-01"], "critical")
        self.assertEqual(severities["HARD-07"], "low")

    def test_env_var_personalizada(self):
        findings = scan(CLEAN, env_var="OTRA_VARIABLE")
        self.assertTrue(any(f["rule"] == "HARD-04" for f in findings))


class TestResumenYBaseline(unittest.TestCase):
    def test_summarize(self):
        s = summarize(scan(DIRTY))
        self.assertEqual(s["verdict"], "FAIL")
        self.assertEqual(s["total"], len(scan(DIRTY)))
        self.assertIn("HARD-01", s["by_rule"])

    def test_baseline_ratchet_sin_cambios(self):
        findings = scan(DIRTY)
        base = make_baseline(findings)
        diff = diff_baseline(findings, base)
        self.assertEqual(diff, {"new": [], "fixed": []})

    def test_baseline_detecta_nuevos_y_corregidos(self):
        findings = scan(DIRTY)
        base = make_baseline(findings)
        fewer = [f for f in findings if f["rule"] != "HARD-07"]
        extra = [f for f in findings if f["rule"] == "HARD-07"]
        diff = diff_baseline(fewer, base)
        self.assertIn("HARD-07:requirements.txt", diff["fixed"])
        self.assertEqual(diff["new"], [])
        diff2 = diff_baseline(extra, [])
        self.assertTrue(diff2["new"])

    def test_carga_baseline_ignora_comentarios(self):
        path = HERE / "fixtures" / "baseline.txt"
        self.assertEqual(load_baseline(path), ["HARD-01:main.go", "HARD-03:main.go"])


if __name__ == "__main__":
    unittest.main()
