"""Local audio transcription helpers for TRIAD/DEMS.

Uses faster-whisper on CPU so the DEMS application does not require CUDA.
The original evidence file is never modified by this module.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

SUPPORTED_AUDIO_EXTENSIONS = {".wav", ".mp3"}
DEFAULT_MODEL = "base"


def is_supported_audio_file(filename: str | Path) -> bool:
    """Return True only for the audio formats currently enabled in DEMS."""
    return Path(filename).suffix.lower() in SUPPORTED_AUDIO_EXTENSIONS


@lru_cache(maxsize=1)
def _get_model(model_name: str = DEFAULT_MODEL):
    """Load the Whisper model once per Flask process."""
    from faster_whisper import WhisperModel

    return WhisperModel(
        model_name,
        device="cpu",
        compute_type="int8",
    )


def transcribe_audio(
    audio_path: str | Path,
    *,
    model_name: str = DEFAULT_MODEL,
    language: str | None = None,
) -> dict[str, Any]:
    """Transcribe WAV/MP3 evidence locally and return forensic segment metadata."""
    path = Path(audio_path)

    if not path.is_file():
        raise FileNotFoundError(f"Audio file not found: {path}")

    if not is_supported_audio_file(path):
        raise ValueError("Only WAV and MP3 audio evidence is supported.")

    model = _get_model(model_name)

    segments, info = model.transcribe(
        str(path),
        language=language,
        beam_size=5,
        vad_filter=True,
    )

    rows: list[str] = []
    segment_records: list[dict[str, Any]] = []

    for segment in segments:
        text = (segment.text or "").strip()

        if not text:
            continue

        start = float(segment.start or 0.0)
        end = float(segment.end or start)

        segment_records.append(
            {
                "start": start,
                "end": end,
                "text": text,
            }
        )

        rows.append(
            f"[{start:09.2f} - {end:09.2f}] {text}"
        )

    transcript = "\n".join(rows).strip()

    if not transcript:
        transcript = "[No speech detected]"

    return {
        "text": transcript,
        "segments": segment_records,
        "segment_count": len(segment_records),
        "language": getattr(info, "language", None) or "unknown",
        "duration_seconds": float(getattr(info, "duration", 0.0) or 0.0),
        "model": model_name,
        "device": "cpu",
        "compute_type": "int8",
    }


def build_transcript_document(
    *,
    source_filename: str | None = None,
    source_evidence_tag: str | None = None,
    result: dict[str, Any] | None = None,
    # Current DEMS route names.  These aliases keep the function compatible
    # with the route already present in the project.
    original_filename: str | None = None,
    transcription: dict[str, Any] | None = None,
) -> str:
    """Build a plain-text forensic transcript suitable for evidence storage."""

    filename = source_filename or original_filename or "unknown"
    transcript_result = result or transcription or {}
    evidence_tag = source_evidence_tag or "unknown"

    return "\n".join(
        [
            "TRIAD — AUDIO TRANSCRIPT",
            "=" * 72,
            f"Source Evidence: {evidence_tag}",
            f"Source Filename: {filename}",
            f"Transcription Model: {transcript_result.get('model', DEFAULT_MODEL)}",
            f"Detected Language: {transcript_result.get('language', 'unknown')}",
            f"Audio Duration (seconds): {transcript_result.get('duration_seconds', 0.0):.2f}",
            "",
            "TRANSCRIPT",
            "-" * 72,
            transcript_result.get("text", ""),
            "",
            "END OF TRANSCRIPT",
        ]
    )
