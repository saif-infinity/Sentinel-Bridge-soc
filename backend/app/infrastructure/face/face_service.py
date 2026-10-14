import base64
import hashlib
import json
import logging
import os
import threading
from pathlib import Path

import cv2
import numpy as np

logger = logging.getLogger(__name__)

FACE_DATA_DIR = Path(__file__).resolve().parents[2] / "face_data"
# Moteur ArcFace (buffalo_s / w600k_mbf) : embeddings 512-d L2-normalises, similarite cosinus
SIMILARITY_THRESHOLD = 0.45
# Fallback Haar : correlation d'histogrammes
HAAR_SIMILARITY_THRESHOLD = 0.78
LIVENESS_TEXTURE_THRESHOLD = 0.15

INSIGHTFACE_ROOT = os.path.join(os.path.expanduser("~"), ".insightface")
INSIGHTFACE_MODEL = "buffalo_s"
EMBEDDING_SIZE = 512
DET_SIZE = (640, 640)


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
            with open(mfile) as f:
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


def _largest_face(faces) -> object:
    """Face avec la plus grande aire de bbox."""

    def area(f):
        try:
            b = f.bbox
            return (b[2] - b[0]) * (b[3] - b[1])
        except Exception:
            return 0

    return max(faces, key=area, default=None)


class FaceService:
    def __init__(self):
        FACE_DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.face_cascade = None
        self._app = None
        self._app_lock = threading.Lock()
        self.engine = "haar"
        self._init_cascade()
        self._init_engine()  # smoke-test au demarrage

    # ------------------------------------------------------------------
    # Initialisation des moteurs
    # ------------------------------------------------------------------
    def _init_cascade(self):
        self.face_cascade = None
        candidates = []
        # 1) Chemin standard via cv2.data (absent sur certains builds opencv)
        try:
            candidates.append(os.path.join(cv2.data.haarcascades, "haarcascade_frontalface_default.xml"))
            candidates.append(os.path.join(cv2.data.haarcascades, "haarcascade_frontalface_alt2.xml"))
        except Exception:
            pass
        # 2) Filet de securite : XML livre a cote du package cv2 installe
        cv2_dir = os.path.dirname(getattr(cv2, "__file__", "") or "") or ""
        for sub in ("data", ""):
            p = os.path.join(cv2_dir, sub, "haarcascade_frontalface_default.xml")
            if p not in candidates:
                candidates.append(p)
        for path in candidates:
            try:
                if os.path.exists(path):
                    cc = cv2.CascadeClassifier(path)
                    if not cc.empty():
                        self.face_cascade = cc
                        logger.info("Fallback Haar cascade loaded: %s", path)
                        return
            except Exception as e:
                logger.warning("Cascade load failed for %s: %s", path, e)
        logger.error("CRITICAL: aucun cascade Haar charge - detection faciale de secours desactivee")

    def _init_engine(self):
        """Charge insightface buffalo_s (SCRFD detection + ArcFace recognition)."""
        try:
            from insightface.app import FaceAnalysis
            app = FaceAnalysis(name=INSIGHTFACE_MODEL, root=INSIGHTFACE_ROOT)
            app.prepare(ctx_id=0, det_size=DET_SIZE)
            self._app = app
            self.engine = "arcface"
            logger.info("Face engine: insightface %s (SCRFD + ArcFace %d-d)", INSIGHTFACE_MODEL, EMBEDDING_SIZE)
        except Exception as e:
            self._app = None
            logger.warning(
                "Engine insightface indisponible (%s) - fallback Haar cascade actif", e
            )

    def _get_app(self):
        if self._app is None:
            with self._app_lock:
                if self._app is None:
                    self._init_engine()
        return self._app

    # ------------------------------------------------------------------
    # Primitives
    # ------------------------------------------------------------------
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

    def _detect_arcface_faces(self, img):
        """Retourne la liste des faces insightface (bbox + kps + embedding), ou None."""
        app = self._get_app()
        if app is None:
            return None
        try:
            faces = app.get(img)
            return faces if faces else None
        except Exception as e:
            logger.error("insightface detection error: %s", e)
            return None

    def _embed_face(self, img, face):
        """Embedding ArcFace 512-d L2-normalise de la face, ou None."""
        try:
            emb = getattr(face, "normed_embedding", None)
            if emb is None or len(emb) != EMBEDDING_SIZE:
                return None
            return np.asarray(emb, dtype=np.float32)
        except Exception as e:
            logger.error("Embedding extraction error: %s", e)
            return None

    def _face_crop(self, img, face):
        bbox = [int(v) for v in face.bbox]
        x1, y1, x2, y2 = bbox
        h, w = img.shape[:2]
        x1, y1 = max(0, x1), max(0, y1)
        x2, y2 = min(w, x2), min(h, y2)
        if x2 <= x1 or y2 <= y1:
            return None
        return img[y1:y2, x1:x2]

    def _load_embedding(self, entry: dict, tenant_id: str):
        """Charge un embedding ArcFace depuis le mapping. None si legacy (histogramme)."""
        if entry.get("engine") != "arcface":
            return None
        fname = entry.get("embed_file")
        if not fname:
            return None
        p = _tenant_dir(tenant_id) / fname
        if not p.exists():
            return None
        try:
            arr = np.load(p)
            if arr.shape != (EMBEDDING_SIZE,):
                return None
            return arr.astype(np.float32)
        except Exception as e:
            logger.warning("Embedding load failed for %s: %s", fname, e)
            return None

    # ------------------------------------------------------------------
    # Détection fallback Haar (conservé : résilience si insightface absent)
    # ------------------------------------------------------------------
    def _detect_face(self, image):
        if self.face_cascade is None:
            return None
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        h, w = gray.shape[:2]
        logger.info("Face detection (Haar) on %dx%d image", w, h)

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

    # ------------------------------------------------------------------
    # Enregistrement
    # ------------------------------------------------------------------
    def register_face(self, username: str, image_data: str, tenant_id: str = "default"):
        img = self._decode_image(image_data)
        if img is None:
            return False, "Invalid image data"

        if self.engine == "arcface":
            return self._register_arcface(username, img, image_data, tenant_id)
        return self._register_haar(username, img, image_data, tenant_id)

    def _register_arcface(self, username: str, img, image_data: str, tenant_id: str):
        faces = self._detect_arcface_faces(img)
        if faces is None:
            return False, "Aucun visage détecté. Veuillez réessayer."

        face = _largest_face(faces)
        emb = self._embed_face(img, face)
        if emb is None:
            return False, "Extraction d'empreinte faciale impossible."

        crop = self._face_crop(img, face)
        # Liveness : non-bloquant en mode arcface (log uniquement - evite les faux rejets webcam)
        if crop is not None:
            gray_crop = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY) if crop.ndim == 3 else crop
            is_live, live = _check_liveness(gray_crop)
            if not is_live:
                logger.warning("Liveness faible lors de l'enregistrement de %s (score %.3f) - non bloquant", username, live)

        image_hash = _hash_image_bytes(image_data)
        tdir = _tenant_dir(tenant_id)
        tdir.mkdir(parents=True, exist_ok=True)
        emb_path = tdir / f"{image_hash}.npy"
        face_img_path = tdir / f"{image_hash}_face.jpg"

        np.save(emb_path, emb)
        try:
            if crop is not None:
                cv2.imwrite(str(face_img_path), cv2.resize(crop, (160, 160)))
        except Exception as e:
            logger.warning("Face crop write failed: %s", e)

        mapping = _read_mapping(tenant_id)
        mapping[username] = {
            "hash": image_hash,
            "embed_file": f"{image_hash}.npy",
            "face_file": f"{image_hash}_face.jpg",
            "engine": "arcface",
        }
        _write_mapping(mapping, tenant_id)
        logger.info("Face enregistree pour %s (engine=arcface)", username)
        return True, "Visage enregistré avec succès"

    def _register_haar(self, username: str, img, image_data: str, tenant_id: str):
        if self.face_cascade is None:
            return False, "Face detection is not available on the server"

        face_roi = self._detect_face(img)
        if face_roi is None:
            return False, "Aucun visage détecté dans l'image."

        gray_roi = face_roi if len(face_roi.shape) == 2 else cv2.cvtColor(face_roi, cv2.COLOR_BGR2GRAY)
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

    # ------------------------------------------------------------------
    # Vérification (identité déclarée)
    # ------------------------------------------------------------------
    def verify_face(self, username: str, image_data: str, tenant_id: str = "default"):
        img = self._decode_image(image_data)
        if img is None:
            return False, "Invalid image data"

        if self.engine == "arcface":
            return self._verify_arcface(username, img, tenant_id)
        return self._verify_haar(username, img, tenant_id)

    def _verify_arcface(self, username: str, img, tenant_id: str):
        faces = self._detect_arcface_faces(img)
        if faces is None:
            return False, "Aucun visage détecté. Veuillez réessayer."

        face = _largest_face(faces)
        emb = self._embed_face(img, face)
        if emb is None:
            return False, "Extraction d'empreinte faciale impossible."

        crop = self._face_crop(img, face)
        if crop is not None:
            gray_crop = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY) if crop.ndim == 3 else crop
            is_live, liveness_score = _check_liveness(gray_crop)
            if not is_live:
                logger.warning("Liveness faible pour %s (score %.3f) - non bloquant", username, liveness_score)

        mapping = _read_mapping(tenant_id)
        user_entry = mapping.get(username)
        if not user_entry:
            return False, "Aucun visage enregistré pour cet utilisateur."

        if user_entry.get("engine") != "arcface":
            return False, "Visage enregistré avec l'ancienne version du moteur. Veuillez vous ré-enregistrer."

        stored_emb = self._load_embedding(user_entry, tenant_id)
        if stored_emb is None:
            return False, "Visage enregistré avec l'ancienne version du moteur. Veuillez vous ré-enregistrer."

        similarity = float(np.dot(emb, stored_emb))
        if similarity >= SIMILARITY_THRESHOLD:
            logger.info("Face verified for %s (sim=%.3f)", username, similarity)
            return True, f"Visage vérifié (similarité: {similarity:.2f})"
        else:
            logger.warning("Face mismatch for %s (sim=%.3f, threshold=%.2f)", username, similarity, SIMILARITY_THRESHOLD)
            return False, f"Le visage ne correspond pas (similarité: {similarity:.2f})."

    def _verify_haar(self, username: str, img, tenant_id: str):
        if self.face_cascade is None:
            return False, "Face detection is not available on the server"

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
        if similarity >= HAAR_SIMILARITY_THRESHOLD:
            logger.info("Face verified for %s (sim=%.3f, live=%.3f)", username, similarity, liveness_score)
            return True, f"Visage vérifié (similarité: {similarity:.2f})"
        else:
            logger.warning("Face mismatch for %s (sim=%.3f, threshold=%.2f)", username, similarity, HAAR_SIMILARITY_THRESHOLD)
            return False, f"Le visage ne correspond pas (similarité: {similarity:.2f})."

    # ------------------------------------------------------------------
    # Identification (visage -> utilisateur OU visiteur inconnu)
    # ------------------------------------------------------------------
    def identify_face(self, image_data: str, tenant_id: str = "default"):
        """
        Identifie le visage parmi les utilisateurs enregistres du tenant.
        Retourne (username|None, best_similarity, message).
        - username si un utilisateur correspond (sim >= SIMILARITY_THRESHOLD)
        - None si c'est un visiteur non autorise (inconnu)
        """
        if self.engine != "arcface" or self._get_app() is None:
            return None, 0.0, "Moteur de reconnaissance faciale indisponible."

        img = self._decode_image(image_data)
        if img is None:
            return None, 0.0, "Invalid image data"

        faces = self._detect_arcface_faces(img)
        if faces is None:
            return None, 0.0, "Aucun visage détecté. Veuillez réessayer."

        face = _largest_face(faces)
        emb = self._embed_face(img, face)
        if emb is None:
            return None, 0.0, "Extraction d'empreinte faciale impossible."

        mapping = _read_mapping(tenant_id)
        best_user, best_sim = None, -1.0
        for uname, entry in mapping.items():
            stored = self._load_embedding(entry, tenant_id)
            if stored is None:
                continue  # entree legacy (ancien moteur) -> ignorée en identification
            sim = float(np.dot(emb, stored))
            if sim > best_sim:
                best_sim, best_user = sim, uname

        if best_user is not None and best_sim >= SIMILARITY_THRESHOLD:
            logger.info("Identify -> %s (sim=%.3f)", best_user, best_sim)
            return best_user, best_sim, f"Utilisateur reconnu : {best_user} (similarité {best_sim:.2f})"

        logger.info("Identify -> inconnu (best sim=%.3f)", best_sim)
        return None, best_sim, "Visiteur non autorisé : aucun utilisateur enregistré ne correspond."

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
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
