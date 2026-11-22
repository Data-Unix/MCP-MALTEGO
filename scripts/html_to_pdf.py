"""Script genérico para compilar informes HTML periciales a PDF mediante Chrome headless sin red."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _find_chrome_executable() -> str:
    candidates = [
        os.environ.get("CHROME_BIN", ""),
        shutil.which("chrome") or "",
        shutil.which("google-chrome") or "",
        shutil.which("chromium") or "",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        str(Path.home() / r"AppData\Local\Google\Chrome\Application\chrome.exe"),
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return "chrome"


def convert_html_to_pdf(html_path: Path, pdf_path: Path) -> int:
    if not html_path.is_file():
        sys.stderr.write(f"Error: el fichero HTML no existe: '{html_path}'\n")
        return 1

    content = html_path.read_text(encoding="utf-8", errors="ignore")
    # Auditoría de seguridad: abortar si contiene referencias a recursos remotos no aislados
    if 'src="http' in content or "src='http" in content:
        sys.stderr.write("Error de seguridad: el HTML contiene recursos remotos 'src=\"http...' no permitidos.\n")
        return 2
    if 'href="http' in content or "href='http" in content:
        sys.stderr.write("Error de seguridad: el HTML contiene enlaces 'href=\"http...' no permitidos.\n")
        return 2

    chrome_bin = _find_chrome_executable()
    tmp_user_data = tempfile.mkdtemp(prefix="maltego_chrome_pdf_")
    try:
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            chrome_bin,
            "--headless=new",
            "--disable-gpu",
            "--no-pdf-header-footer",
            "--disable-background-networking",
            "--disable-component-update",
            "--no-first-run",
            "--disable-sync",
            "--metrics-recording-only",
            "--disable-default-apps",
            "--disable-domain-reliability",
            f"--user-data-dir={tmp_user_data}",
            f"--print-to-pdf={pdf_path.resolve()}",
            str(html_path.resolve()),
        ]

        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode == 0 and pdf_path.exists():
            sys.stdout.write(f"PDF generado correctamente en: {pdf_path} ({pdf_path.stat().st_size} bytes)\n")
            return 0
        sys.stderr.write(f"Error al generar PDF (código {res.returncode}): {res.stderr or res.stdout}\n")
        return res.returncode or 1
    finally:
        shutil.rmtree(tmp_user_data, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="html_to_pdf",
        description="Compila un informe HTML a PDF utilizando Chrome headless con aislamiento total de red.",
    )
    parser.add_argument("html_file", type=Path, help="Ruta al archivo HTML de origen")
    parser.add_argument("pdf_file", type=Path, help="Ruta al archivo PDF de destino")
    args = parser.parse_args(argv)

    return convert_html_to_pdf(args.html_file, args.pdf_file)


if __name__ == "__main__":
    sys.exit(main())
