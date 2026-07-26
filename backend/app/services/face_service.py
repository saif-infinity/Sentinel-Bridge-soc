import os
import base64
import json
import hashlib
import logging
from pathlib import Path

import cv2
import numpy as np

logger = logging.getLogger(__name__)

FACE_DATA_DIR = Path(__file__).resolve().parent.parent / "face_data"
SIMILARITY_THRESHOLD = 0.78
LIVENESS_TEXTURE_THRESHOLD = 0.15


def _hash_image_bytes(image_data: str) -> str:
    if "," in image_data:
        image_data = image_data.split(",")[1]
    return hashlib.sha256(image_data.encode()).hexdigest()


def _tenant_dir(tenant_id: str) -> Path:
    """Get tenant-specific face data directory."""
    return FACE_DATA_DIR / tenant_id


def _mapping_file(tenant_id: str) -> Path:
    """Get tenant-specific mapping file."""
    return _tenant_dir(tenant_id) / "face_mapping.json"


def _read_mapping(tenant_id: str = "default") -> dict:
    mfile = _mapping_file(tenant_id)
    if mfile.exists():
        try:
            with open(mfile, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, Exception):
            return {}
    return {}


def _write_mapping(mapping: dict, tenant_id: str = "default"):
    tdir = _tenant_dir(tenant_id)
    tdir.mkdir(parents=True, exist_ok=True)
    with open(_mapping_file(tenant_id), "w") as f:
        json.dump(mapping, f, indent=2)


def _check_liveness(face_roi_gray: np.ndarray) -> tuple:
    """
    Basic liveness detection using texture analysis.
    Real faces have high-frequency detail (skin pores, fine textures).
    Printed photos have lower high-frequency content.
    Returns (is_live: bool, confidence: float).
    """
    h, w = face_roi_gray.shape
    if h < 20 or w < 20:
        return True, 0.5

    face_resized = cv2.resize(face_roi_gray, (128, 128))
    fft = np.fft.fft2(face_resized)
    fft_shift = np.fft.fftshift(fft)
    magnitude = np.log(np.abs(fft_shift) + 1e-8)

    cx, cy = 64, 64
    mask_high = np.zeros((128, 128), dtype=np.uint8)
    cv2.circle(mask_high, (cx, cy), 40, 1, -1)
    mask_high = 1 - mask_high

    high_freq = np.mean(magnitude * mask_high)
    low_freq = np.mean(magnitude * (1 - mask_high))
    ratio = high_freq / (low_freq + 1e-8)

    is_live = ratio > LIVENESS_TEXTURE_THRESHOLD
    return is_live, float(ratio)


class FaceService:
    def __init__(self):
        FACE_DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.face_cascade = None
        self._init_cascade()

    def _init_cascade(self):
        try:
            cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
            if not os.path.exists(cascade_path):
                cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_alt2.xml"
            self.face_cascade = cv2.CascadeClassifier(cascade_path)
            if self.face_cascade.empty():
                logger.error("Failed to load Haar cascade for face detection")
                self.face_cascade = None
            else:
                logger.info("Face detection cascade loaded successfully")
        except Exception as e:
            logger.error("Error loading face cascade: %s", e)
            self.face_cascade = None

    def _decode_image(self, image_data: str):
        try:
            if "," in image_data:
                image_data = image_data.split(",")[1]
            img_bytes = base64.b64decode(image_data)
            nparr = np.frombuffer(img_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            return img
        except Exception as e:
            logger.error("Error decoding image: %s", e)
            return None

    def _detect_face(self, image):
        if self.face_cascade is None:
            return None
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        h, w = gray.shape[:2]
        logger.info("Face detection on %dx%d image", w, h)

        if h < 150 or w < 150:
            scale = max(2, 400 // max(h, w))
            gray = cv2.resize(gray, (w * scale, h * scale), interpolation=cv2.INTER_LINEAR)
            h, w = gray.shape
            logger.info("  upscaled to %dx%d", w, h)

        def _try_pass(img, label):
            for sf, nn, ms in [
                (1.1,  3, (60, 60)),
                (1.08, 2, (50, 50)),
                (1.05, 2, (40, 40)),
                (1.03, 1, (30, 30)),
            ]:
                faces = self.face_cascade.detectMultiScale(img, sf, nn, minSize=ms)
                if len(faces) > 0:
                    logger.info("  %s pass sf=%.2f nn=%d ms=%s -> found %d", label, sf, nn, ms, len(faces))
                    return faces
            return None

        gamma = 1.3
        inv = 1.0 / gamma
        table = np.array([((i / 255.0) ** inv) * 255 for i in range(256)], dtype=np.uint8)
        bright = cv2.LUT(gray, table)
        faces = _try_pass(bright, "gamma")
        if faces is not None:
            (x, y, fw, fh) = faces[0]
            return gray[y:y + fh, x:x + fw]

        faces = _try_pass(gray, "gray")
        if faces is not None:
            (x, y, fw, fh) = faces[0]
            return gray[y:y + fh, x:x + fw]

        eq = cv2.equalizeHist(gray)
        faces = _try_pass(eq, "equalize")
        if faces is not None:
            (x, y, fw, fh) = faces[0]
            return gray[y:y + fh, x:x + fw]

        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        faces = _try_pass(enhanced, "clahe")
        if faces is not None:
            (x, y, fw, fh) = faces[0]
            return gray[y:y + fh, x:x + fw]

        if max(h, w) < 480:
            scale = max(2, 480 // max(h, w))
            big = cv2.resize(gray, (w * scale, h * scale), interpolation=cv2.INTER_LINEAR)
            faces = _try_pass(big, "upscaled")
            if faces is not None:
                (x, y, fw, fh) = faces[0]
                x //= scale; y //= scale; fw //= scale; fh //= scale
                return gray[y:y + fh, x:x + fw]

        logger.info("  face not found after all passes")
        return None

    def _extract_face_encoding(self, face_roi):
        face_resized = cv2.resize(face_roi, (160, 160))
        face_blur = cv2.GaussianBlur(face_resized, (3, 3), 0)

        hist_lbp = cv2.calcHist([face_blur], [0], None, [256], [0, 256])
        cv2.normalize(hist_lbp, hist_lbp)

        face_edges = cv2.Canny(face_blur, 50, 150)
        edge_hist = cv2.calcHist([face_edges], [0], None, [256], [0, 256])
        cv2.normalize(edge_hist, edge_hist)

        combined = np.vstack([hist_lbp, edge_hist])
        cv2.normalize(combined, combined)
        return combined

    def register_face(self, username: str, image_data: str, tenant_id: str = "default"):
        if self.face_cascade is None:
            return False, "Face detection is not available on the server"

        img = self._decode_image(image_data)
        if img is None:
            return False, "Invalid image data"

        face_roi = self._detect_face(img)
        if face_roi is None:
            return False, "Aucun visage détecté dans l'image."

        gray_roi = cv2.cvtColor(
            cv2.cvtColor(face_roi, cv2.COLOR_GRAY2BGR) if len(face_roi.shape) == 2 else face_roi,
            cv2.COLOR_BGR2GRAY
        ) if len(face_roi.shape) == 2 else face_roi
        if len(gray_roi.shape) == 3:
            gray_roi = cv2.cvtColor(gray_roi, cv2.COLOR_BGR2GRAY)
        is_live, liveness_score = _check_liveness(gray_roi)
        if not is_live:
            logger.warning("Liveness check failed for registration of %s (score: %.3f)", username, liveness_score)
            return False, "Détection de spoofing: l'image semble être une photo. Utilisez un visage réel."

        image_hash = _hash_image_bytes(image_data)
        hist = self._extract_face_encoding(face_roi)

        tdir = _tenant_dir(tenant_id)
        tdir.mkdir(parents=True, exist_ok=True)
        hist_path = tdir / f"{image_hash}.npy"
        face_img_path = tdir / f"{image_hash}_face.jpg"

        np.save(hist_path, hist)
        face_resized = cv2.resize(face_roi, (160, 160))
        cv2.imwrite(str(face_img_path), face_resized)

        mapping = _read_mapping(tenant_id)
        mapping[username] = {
            "hash": image_hash,
            "hist_file": f"{image_hash}.npy",
            "face_file": f"{image_hash}_face.jpg",
        }
        _write_mapping(mapping, tenant_id)

        return True, "Visage enregistré avec succès"

    def verify_face(self, username: str, image_data: str, tenant_id: str = "default"):
        if self.face_cascade is None:
            return False, "Face detection is not available on the server"

        img = self._decode_image(image_data)
        if img is None:
            return False, "Invalid image data"

        face_roi = self._detect_face(img)
        if face_roi is None:
            return False, "Aucun visage détecté. Veuillez réessayer."

        gray_roi = face_roi if len(face_roi.shape) == 2 else cv2.cvtColor(face_roi, cv2.COLOR_BGR2GRAY)
        is_live, liveness_score = _check_liveness(gray_roi)
        if not is_live:
            logger.warning("Liveness check failed for %s (score: %.3f)", username, liveness_score)
            return False, "Détection de spoofing: utilisez un visage réel, pas une photo."

        mapping = _read_mapping(tenant_id)
        user_entry = mapping.get(username)
        if not user_entry:
            return False, "Aucun visage enregistré pour cet utilisateur."

        hist_path = _tenant_dir(tenant_id) / user_entry["hist_file"]
        if not hist_path.exists():
            return False, "Données faciales introuvables."

        stored_hist = np.load(hist_path)
        new_hist = self._extract_face_encoding(face_roi)

        similarity = cv2.compareHist(stored_hist, new_hist, cv2.HISTCMP_CORREL)

        if similarity >= SIMILARITY_THRESHOLD:
            logger.info("Face verified for %s (sim=%.3f, live=%.3f)", username, similarity, liveness_score)
            return True, f"Visage vérifié (similarité: {similarity:.2f})"
        else:
            logger.warning("Face mismatch for %s (sim=%.3f, threshold=%.2f)", username, similarity, SIMILARITY_THRESHOLD)
            return False, f"Le visage ne correspond pas (similarité: {similarity:.2f})."

    def has_registered_face(self, username: str, tenant_id: str = "default"):
        mapping = _read_mapping(tenant_id)
        return username in mapping

    def get_face_path(self, username: str, tenant_id: str = "default"):
        mapping = _read_mapping(tenant_id)
        entry = mapping.get(username)
        if not entry:
            return None
        face_path = _tenant_dir(tenant_id) / entry["face_file"]
        return str(face_path) if face_path.exists() else None


face_service = FaceService()
