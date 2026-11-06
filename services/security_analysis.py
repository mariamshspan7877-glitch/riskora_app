import hashlib
import io
import os
import re
from zipfile import BadZipFile, ZipFile

from docx import Document
from docx.opc.exceptions import PackageNotFoundError
from pypdf import PdfReader
from pypdf.errors import FileNotDecryptedError, PdfReadError

ALLOWED_EXTENSIONS = {".txt", ".csv", ".json", ".xml", ".md", ".log", ".pdf", ".docx", ".png", ".jpg", ".jpeg", ".gif", ".bmp"}
TEXT_EXTENSIONS = {".txt", ".csv", ".json", ".xml", ".md", ".log"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp"}
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SENSITIVE_KEYWORDS = [
    "password",
    "secret",
    "api_key",
    "token",
    "private key",
    "aws_secret_access_key",
    "authorization",
    "access token",
    "client_secret",
]


def safe_filename(value):
    cleaned = os.path.basename(value or "")
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", cleaned).strip("._")
    return cleaned or "uploaded_file"


def infer_file_extension(data):
    if data.startswith(b"%PDF"):
        return ".pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if data.startswith(b"BM"):
        return ".bmp"

    try:
        with ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
            if "[Content_Types].xml" in names and "word/document.xml" in names:
                return ".docx"
    except BadZipFile:
        pass

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" not in text:
        return ".txt"
    return None


def validate_uploaded_file(file_storage, max_size):
    if file_storage is None or not getattr(file_storage, "filename", None):
        raise ValueError("No file selected.")

    filename = safe_filename(file_storage.filename)
    extension = os.path.splitext(filename)[1].lower()

    file_storage.seek(0, os.SEEK_END)
    size = file_storage.tell()
    file_storage.seek(0)

    if size <= 0:
        raise ValueError("The uploaded file is empty.")
    if size > max_size:
        raise ValueError(f"The uploaded file exceeds the supported size limit of {max_size / (1024 * 1024):.1f} MB.")

    data = file_storage.read()
    file_storage.seek(0)

    if extension not in ALLOWED_EXTENSIONS:
        if extension:
            raise ValueError("Unsupported file type. Allowed types include TXT, CSV, JSON, XML, MD, LOG, PDF, DOCX, PNG, JPG, GIF, BMP.")
        extension = infer_file_extension(data)
        if extension is None:
            raise ValueError("This file has no extension and its type could not be identified. Try a DOCX, PDF, image, or text file.")

    sample = data[:512]
    if extension == ".pdf" and not sample.startswith(b"%PDF"):
        raise ValueError("The uploaded PDF file appears to be invalid or corrupted.")
    if extension in IMAGE_EXTENSIONS and not sample[:8].startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM")):
        raise ValueError("The uploaded image does not match the expected signature.")

    return {"filename": filename, "extension": extension, "size": size}


def sha256_of_bytes(data):
    return hashlib.sha256(data).hexdigest()


def analyze_text(text):
    findings = []
    emails = EMAIL_PATTERN.findall(text)
    if emails:
        findings.append({
            "id": "email-pattern",
            "severity": "medium",
            "title": "Email addresses detected in file contents",
            "description": "The file contains one or more email addresses in plain text.",
            "evidence": ", ".join(sorted(set(emails))[:5]),
            "impact": "Exposed contact details can increase privacy risk when the file is stored or shared.",
            "remediation": "Remove or mask personal contact details before storing the file in cloud storage.",
            "confidence": "High",
            "category": "sensitive-data",
        })

    matches = [keyword for keyword in SENSITIVE_KEYWORDS if keyword.lower() in text.lower()]
    if matches:
        findings.append({
            "id": "secret-pattern",
            "severity": "high",
            "title": "Potential secrets or credentials detected",
            "description": "The file contains sensitive keywords that may indicate embedded credentials or private identifiers.",
            "evidence": ", ".join(matches[:5]),
            "impact": "Leaked secrets can enable unauthorized access to systems or accounts.",
            "remediation": "Review these references and remove any real credentials or tokens before uploading.",
            "confidence": "Medium",
            "category": "sensitive-data",
        })
    return findings


def analyze_uploaded_file(file_storage, extension=None):
    file_storage.seek(0)
    data = file_storage.read()
    file_storage.seek(0)
    filename = safe_filename(file_storage.filename)
    extension = extension or os.path.splitext(filename)[1].lower() or infer_file_extension(data)
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("The uploaded file type could not be identified for analysis.")
    file_type = "text" if extension in TEXT_EXTENSIONS else "image" if extension in IMAGE_EXTENSIONS else "document"

    findings = []

    if extension in TEXT_EXTENSIONS:
        findings = analyze_text(data.decode("utf-8", errors="ignore"))
    elif extension == ".pdf":
        try:
            reader = PdfReader(io.BytesIO(data), strict=False)
            if reader.is_encrypted:
                raise ValueError("Password-protected PDF files cannot be analyzed. Remove the password and try again.")
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
        except (FileNotDecryptedError, PdfReadError) as exc:
            raise ValueError("The PDF could not be read. Check that the file is valid and not corrupted.") from exc

        if text.strip():
            findings = analyze_text(text)
        else:
            findings.append({
                "id": "pdf-no-extractable-text",
                "severity": "low",
                "title": "No searchable text found in PDF",
                "description": "The PDF has no extractable text. Scanned pages and embedded images are not checked because OCR is not enabled.",
                "evidence": "PDF text extraction completed without finding searchable text.",
                "impact": "Sensitive content in scanned pages may not be detected by this assessment.",
                "remediation": "Review scanned pages manually before sharing or storing the PDF.",
                "confidence": "High",
                "category": "analysis-limitation",
            })
    elif extension == ".docx":
        try:
            document = Document(io.BytesIO(data))
        except (BadZipFile, PackageNotFoundError) as exc:
            raise ValueError("The Word document could not be read. Check that it is a valid, uncorrupted DOCX file.") from exc

        text_parts = [paragraph.text for paragraph in document.paragraphs]
        text_parts.extend(
            cell.text
            for table in document.tables
            for row in table.rows
            for cell in row.cells
        )
        text = "\n".join(text_parts)
        if text.strip():
            findings = analyze_text(text)
        else:
            findings.append({
                "id": "docx-no-extractable-text",
                "severity": "low",
                "title": "No text found in Word document",
                "description": "No searchable text was found in the document paragraphs or tables.",
                "evidence": "Word document text extraction completed without finding searchable text.",
                "impact": "Content in embedded images, comments, or other objects may not be detected.",
                "remediation": "Review embedded images and document comments manually before sharing or storing the file.",
                "confidence": "High",
                "category": "analysis-limitation",
            })
    elif extension in IMAGE_EXTENSIONS:
        findings.append({
            "id": "image-content-not-scanned",
            "severity": "low",
            "title": "Image contents were not scanned for sensitive text",
            "description": "This assessment does not inspect image pixels or use OCR to detect text within images.",
            "evidence": f"Image file type: {extension.lstrip('.').upper()}.",
            "impact": "Sensitive information visible in the image may not be detected.",
            "remediation": "Review the image visually before sharing or storing it.",
            "confidence": "High",
            "category": "analysis-limitation",
        })

    if not findings:
        findings.append({
            "id": "baseline-review",
            "severity": "low",
            "title": "No direct sensitive content detected in the scanned payload",
            "description": "The local assessment did not find obvious sensitive patterns in the file content.",
            "evidence": "Static file review and content pattern checks completed.",
            "impact": "This does not guarantee the file is risk-free; it only means no immediate identifiers were detected.",
            "remediation": "Continue to review the business context and storage policy before upload.",
            "confidence": "Medium",
            "category": "assessment",
        })

    return {
        "filename": filename,
        "file_type": file_type,
        "file_size": len(data),
        "sha256": sha256_of_bytes(data),
        "findings": findings,
    }
