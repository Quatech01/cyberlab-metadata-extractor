import io
import threading
import time
import urllib.request

import piexif
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from PIL import Image
from pypdf import PdfWriter

app = FastAPI()


def _make_vuln_jpeg() -> bytes:
    """JPEG with GPS coordinates, author email, camera make/model, and software version."""
    img = Image.new("RGB", (16, 16), color=(128, 64, 32))
    exif_dict = {
        "0th": {
            piexif.ImageIFD.Make: b"Canon",
            piexif.ImageIFD.Model: b"Canon EOS 5D Mark IV",
            piexif.ImageIFD.Software: b"Adobe Photoshop CS6 13.0.1",
            piexif.ImageIFD.Artist: b"j.smith@contoso-internal.com",
            piexif.ImageIFD.Copyright: b"John Smith - Contoso Ltd 2024",
            piexif.ImageIFD.DateTime: b"2024:03:15 09:30:00",
        },
        "Exif": {},
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((51, 1), (30, 1), (26, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"W",
            piexif.GPSIFD.GPSLongitude: ((0, 1), (7, 1), (40, 1)),
            piexif.GPSIFD.GPSAltitudeRef: 0,
            piexif.GPSIFD.GPSAltitude: (12, 1),
        },
        "1st": {},
        "thumbnail": None,
    }
    exif_bytes = piexif.dump(exif_dict)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif_bytes)
    return buf.getvalue()


def _make_safe_jpeg() -> bytes:
    """JPEG with no EXIF metadata — clean file."""
    img = Image.new("RGB", (16, 16), color=(32, 128, 192))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def _make_vuln_pdf() -> bytes:
    """PDF with author email, software version, and confidential subject line."""
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.add_metadata(
        {
            "/Author": "j.davies@contoso-internal.com",
            "/Creator": "Microsoft Word 16.0.14326",
            "/Producer": "Microsoft Office 2019",
            "/Subject": "Q4 Financial Summary - CONFIDENTIAL INTERNAL USE ONLY",
            "/Title": "Quarterly Financial Report",
            "/Keywords": "internal confidential quarterly earnings forecast",
        }
    )
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _make_safe_pdf() -> bytes:
    """PDF with metadata stripped — clean file."""
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


_FILES: dict[str, tuple[bytes, str]] = {}


@app.on_event("startup")
def _build_files() -> None:
    global _FILES
    _FILES = {
        "vuln_photo.jpg": (_make_vuln_jpeg(), "image/jpeg"),
        "safe_photo.jpg": (_make_safe_jpeg(), "image/jpeg"),
        "vuln_document.pdf": (_make_vuln_pdf(), "application/pdf"),
        "safe_document.pdf": (_make_safe_pdf(), "application/pdf"),
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/files")
def list_files():
    return {"files": list(_FILES.keys())}


@app.get("/files/{filename}")
def get_file(filename: str):
    entry = _FILES.get(filename)
    if entry is None:
        raise HTTPException(status_code=404, detail="File not found")
    content, media_type = entry
    return Response(content=content, media_type=media_type)


def start(port: int = 3000):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(30):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
            break
        except Exception:
            time.sleep(0.2)
    return server


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=3000)
