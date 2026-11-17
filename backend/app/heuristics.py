from __future__ import annotations

import os
from typing import Any


def get_model_status(model_path: str) -> dict[str, Any]:
    if not os.path.exists(model_path):
        return {
            "available": False,
            "model_path": model_path,
            "message": "Optional Random Forest model artifact is not bundled. Heuristics are active and the ML component is unavailable.",
            "version": "n/a",
        }

    try:
        import joblib

        model = joblib.load(model_path)
        return {
            "available": True,
            "model_path": model_path,
            "message": "Model artifact loaded successfully.",
            "version": getattr(model, "__class__", type(model)).__name__,
        }
    except Exception as exc:  # pragma: no cover - defensive behavior
        return {
            "available": False,
            "model_path": model_path,
            "message": f"Model artifact exists but failed to load: {exc}",
            "version": "n/a",
        }
