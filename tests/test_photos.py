"""Photos: the way a phone stores them, and what must not leave with them.

Three claims. The redaction lands on the words even when the pixels are stored
sideways and only an EXIF tag says which way is up. A photo goes out in the
format it came in. And nothing about where or how it was taken goes with it.
"""

from __future__ import annotations

import io

import pytest

from stripii import ocr, redact_file
from stripii.document import GREEN

from .conftest import ocr_backends, requires_any_ocr, requires_heif, write_photo

pytestmark = [requires_any_ocr, pytest.mark.slow]

IDENTIFIERS = ["Margaret Whitfield", "4471982", "412-88-9031", "m.whitfield@example.com"]


def _read_back(data: bytes, suffix: str, engine: str) -> str:
    from PIL import Image

    if suffix in {".heic", ".heif"}:
        import pillow_heif

        pillow_heif.register_heif_opener()
    return ocr.read_images([Image.open(io.BytesIO(data)).convert("RGB")], backend=engine).text


@pytest.mark.parametrize("engine", ocr_backends())
def test_a_sideways_photo_is_turned_the_right_way_up_before_reading(tmp_path, engine):
    """Stored rotated with orientation 6, as an upright iPhone shot is."""
    photo = tmp_path / "sideways.jpg"
    write_photo(photo, orientation=6)
    from PIL import Image

    with Image.open(photo) as stored:
        assert stored.size == (1000, 1400)         # sideways on disk
    page = ocr.load_image(photo)[0]
    assert page.size == (1400, 1000)               # upright once loaded

    result = redact_file(photo, profile="health", outputs=("text", "image"), ocr=engine)
    for identifier in IDENTIFIERS:
        assert identifier not in result.text
    assert result.grade == GREEN, result.reasons
    after = _read_back(result.outputs["image"], ".jpg", engine)
    assert "Whitfield" not in after and "4471982" not in after
    assert "Hemoglobin" in after


@pytest.mark.parametrize("suffix", [".jpg", ".png"])
def test_a_photo_goes_out_in_its_own_format_with_no_metadata(tmp_path, suffix):
    from PIL import Image

    photo = tmp_path / f"card{suffix}"
    write_photo(photo)
    if suffix == ".jpg":
        with Image.open(photo) as stored:
            assert stored.getexif()                # the fixture carries EXIF in
    result = redact_file(photo, profile="health", outputs=("image",), ocr=ocr_backends()[0])
    out = Image.open(io.BytesIO(result.outputs["image"]))
    assert out.format == {".jpg": "JPEG", ".png": "PNG"}[suffix]
    assert not out.getexif()
    assert "exif" not in out.info and "xmp" not in out.info


@requires_heif
def test_heic_in_heic_out(tmp_path):
    import pillow_heif
    from PIL import Image

    pillow_heif.register_heif_opener()
    photo = tmp_path / "card.heic"
    write_photo(photo)
    engine = ocr_backends()[0]
    result = redact_file(photo, profile="health", outputs=("text", "image"), ocr=engine)
    assert result.grade == GREEN, result.reasons
    out = Image.open(io.BytesIO(result.outputs["image"]))
    assert out.format == "HEIF"
    assert not out.getexif()
    after = _read_back(result.outputs["image"], ".heic", engine)
    assert "Whitfield" not in after and "Hemoglobin" in after


def test_unknown_image_suffixes_are_refused():
    from PIL import Image

    with pytest.raises(ValueError, match="cannot write"):
        ocr.image_bytes(Image.new("RGB", (10, 10)), ".gif")
