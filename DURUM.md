# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — Proje oluşturuldu, test edildi, CI eklendi

- Konu: Portföydeki farklı araçların `--format json` çıktısını tek bir risk panosunda birleştiren meta-araç. Genel, araç-bağımsız bir sözleşmeye dayanıyor (bir liste ya da `"findings"` anahtarlı bir dict, her finding'de bir `severity` alanı) — bu, portföydeki 15 aracın hepsinin zaten ürettiği şekil, ama bu proje hiçbirine kod bağımlılığı olmadan sadece JSON tüketiyor.
- Her kaynak için ağırlıklı risk skoru hesaplanıyor (HIGH=10, MEDIUM=5, LOW=1, UNKNOWN=2) ve kaynaklar riske göre sıralanıyor.
- `sample_reports/` klasöründe **gerçek, değiştirilmemiş** 4 JSON raporu var — `Dockerfile-Security-Linter`, `Cloud-IAM-Policy-Auditor`, `DNS-Security-Auditor` (google.com'a karşı gerçek çalıştırma) ve `JWT-Security-Analyzer`'ın kendi örnekleriyle gerçekten üretilmiş çıktıları. Bu, portföy içi araçların gerçekten birlikte çalışabildiğini gösteren otantik bir entegrasyon örneği.
- Dosya: `security_findings_aggregator.py`, `tests/test_security_findings_aggregator.py` (18 test), `pyproject.toml`, `.github/workflows/ci.yml`.
- Baştan itibaren eklenenler: `--format json`, `--fail-on {none,medium,high}`.
- Durum: ✅ 18/18 test gerçekten çalıştırılıp geçti, `ruff check .` temiz (bir implicit string concatenation uyarısı `.format()` ile düzeltildi). CLI 4 gerçek fixture'a karşı gerçekten çalıştırıldı: 8 HIGH + 2 MEDIUM + 1 LOW, risk skoru 91 — `sample_report.md` bu gerçek çalıştırmadan üretildi. Henüz push edilmedi (repo local).

**Sıradaki iş:** GitHub'da `Security-Findings-Aggregator` adıyla repo aç, git init + push.
