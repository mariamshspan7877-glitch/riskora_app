# Riskora

Riskora is a cloud-based file security and risk assessment platform for a university Cloud Computing project.

## Features
- Secure registration and login
- File upload and local assessment engine
- Risk scoring and policy-aware review
- Detailed findings and PDF generation
- Google Cloud Storage readiness checks
- Audit logging, history, and reports

The local scanner checks text-based files and extracts searchable text from PDFs and DOCX paragraphs/tables for common sensitive-data patterns. It accepts image files but does not scan their pixels or run OCR. Content in embedded document images, comments, macros, and other objects may not be detected. The scanner is not an antivirus or malware detector.

## Quick Start

```bash
cd Riskora
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
python app.py
```

## Environment variables
See `.env.example` for required variables.

## Testing

```bash
pytest -q
```

## Notes
This project intentionally keeps sensitive file content local and does not claim malware detection without verified results.
