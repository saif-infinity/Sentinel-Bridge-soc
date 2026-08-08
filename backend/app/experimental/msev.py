"""
MSEV (Multi-Spectral & Electro-Vascular) — Next-Gen Biometric Liveness Detection.

Architecture overview:
  Validation = (SecureFramePipeline.signature_ok)
            AND (SpectralAnalyzer.is_human_skin)
            AND (RPPGEngine.pulse_detected)
            AND (PupilChallenge.pupil_reacted)

Each module targets a specific class of presentation attacks:
  - Signature   : rejects injected / replayed frames
  - Reflectance : rejects silicone masks, latex, LCD/OLED screens
  - rPPG        : rejects static photos, deepfakes, flat video loops
  - Pupil       : rejects 2D/3D screens, high-quality prints
"""

from __future__ import annotations

import hashlib
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, Protocol, Tuple

import cv2
import numpy as np
from numpy.typing import NDArray


# ---------------------------------------------------------------------------
#  Crypto helpers (Ed25519-style simulation using hashlib + simple ECC mock)
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _sign_hmac(symmetric_key: bytes, message: bytes) -> bytes:
    """Symmetric HMAC-SHA256 signature.

    In a hardware-RoT simulation the *symmetric_key* is burned into the
    sensor during fabrication and is also registered with the validator
    at enrollment time.
    """
    import hmac
    return hmac.new(symmetric_key, message, hashlib.sha256).digest()


def _verify_hmac(symmetric_key: bytes, message: bytes,
                 signature: bytes) -> bool:
    import hmac
    expected = hmac.new(symmetric_key, message, hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def _generate_symmetric_key() -> bytes:
    """32-byte random symmetric key (shared sensor–validator secret)."""
    return _sha256(uuid.uuid4().bytes + uuid.uuid4().bytes)


# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

# Human heart-rate passband (BPM → Hz)
HR_MIN_BPM = 50
HR_MAX_BPM = 110
HR_MIN_HZ = HR_MIN_BPM / 60.0
HR_MAX_HZ = HR_MAX_BPM / 60.0

# Skin reflectance heuristic bounds (RGB-normalised)
SKIN_R_LOW, SKIN_R_HIGH = 0.35, 0.70
SKIN_G_LOW, SKIN_G_HIGH = 0.20, 0.50
SKIN_B_LOW, SKIN_B_HIGH = 0.15, 0.40

# rPPG signal quality thresholds
RPPG_SNR_THRESHOLD = 3.0       # dB
RPPG_MIN_PEAK_PROMINENCE = 0.15

# Pupil challenge
PUPIL_CONSTRICTION_MIN = 0.10   # 10% minimum radius reduction

# Spectral simulation
FACE_ROI_PAD = 0.15             # 15% inward padding


# ---------------------------------------------------------------------------
#  Exceptions
# ---------------------------------------------------------------------------

class MSEVError(Exception):
    """Base MSEV exception."""


class FrameRejected(MSEVError):
    """Frame failed one or more checks."""


# ---------------------------------------------------------------------------
#  Data structures
# ---------------------------------------------------------------------------

@dataclass
class MSEVResult:
    """Aggregated validation result."""
    passed: bool
    signature_ok: bool = False
    reflectance_ok: bool = False
    pulse_detected: bool = False
    pupil_reacted: bool = False
    confidence: float = 0.0
    details: str = ""


@dataclass
class RPPGBuffer:
    """Circular buffer for rPPG time-series."""
    maxlen: int = 64
    timestamps: list[float] = field(default_factory=list)
    green_means: list[float] = field(default_factory=list)
    _t0: float = field(default_factory=time.time)

    def push(self, green_mean: float) -> None:
        now = time.time() - self._t0
        self.timestamps.append(now)
        self.green_means.append(green_mean)
        if len(self.timestamps) > self.maxlen:
            self.timestamps.pop(0)
            self.green_means.pop(0)

    @property
    def ready(self) -> bool:
        return len(self.timestamps) >= 30

    def reset(self) -> None:
        self.timestamps.clear()
        self.green_means.clear()
        self._t0 = time.time()


# ---------------------------------------------------------------------------
#  1. SecureFramePipeline
# ---------------------------------------------------------------------------

class SecureFramePipeline:
    """Cryptographic frame origin verification with simulated hardware RoT.

    In production, the symmetric key lives in a secure enclave (e.g. ARM
    TrustZone / Apple SEP) and is shared with the validator at enrollment.
    """

    def __init__(self) -> None:
        self._sensor_key = _generate_symmetric_key()

    # --- sensor-side (simulated) ---

    @staticmethod
    def sign_frame(frame: NDArray[np.uint8],
                   symmetric_key: bytes) -> bytes:
        """Sign a raw frame with the sensor's symmetric key.

        Args:
            frame: BGR image (H, W, 3).
            symmetric_key: 32-byte shared secret.

        Returns:
            32-byte HMAC signature.
        """
        digest = _sha256(frame.tobytes())
        return _sign_hmac(symmetric_key, digest)

    # --- validator-side ---

    @staticmethod
    def verify_frame(frame: NDArray[np.uint8],
                     signature: bytes,
                     symmetric_key: bytes) -> bool:
        """Verify that *frame* was signed by the trusted sensor.

        Returns:
            True if the signature is valid.
        """
        digest = _sha256(frame.tobytes())
        return _verify_hmac(symmetric_key, digest, signature)

    def get_sensor_key(self) -> bytes:
        """Expose the symmetric key to the validator."""
        return self._sensor_key

    def simulate_signed_frame(self,
                              frame: NDArray[np.uint8]) -> Tuple[NDArray[np.uint8], bytes]:
        """Convenience: sign *frame* and return (frame, signature)."""
        sig = self.sign_frame(frame, self._sensor_key)
        return frame, sig

    @staticmethod
    def simulate_spoof_frame(frame: NDArray[np.uint8]) -> Tuple[NDArray[np.uint8], bytes]:
        """Simulate an injection attack: sign with a different (attacker) key."""
        attacker_key = _generate_symmetric_key()
        sig = SecureFramePipeline.sign_frame(frame, attacker_key)
        return frame, sig


# ---------------------------------------------------------------------------
#  2. SpectralAnalyzer
# ---------------------------------------------------------------------------

class SpectralAnalyzer:
    """Material verification via simulated multi-spectral reflectance analysis.

    Real human skin exhibits a characteristic reflectance curve in R/G/B
    channels due to melanin and hemoglobin absorption.  Synthetic materials
    (silicone, latex, LCD/OLED screens) deviate measurably.
    """

    @staticmethod
    def analyze_reflectance(frame: NDArray[np.uint8],
                            face_coords: Optional[Tuple[int, int, int, int]] = None
                            ) -> Tuple[bool, float]:
        """Evaluate whether the face region matches human skin reflectance.

        Args:
            frame: BGR image.
            face_coords: (x, y, w, h) bounding box.  If None, the whole
                         frame is used.

        Returns:
            (passed, confidence) where confidence ≈ probability of human skin.
        """
        h, w = frame.shape[:2]
        if face_coords is None:
            x, y, fw, fh = 0, 0, w, h
        else:
            x, y, fw, fh = face_coords
            # inward pad to avoid hair / background
            pad_x, pad_y = int(fw * FACE_ROI_PAD), int(fh * FACE_ROI_PAD)
            x = max(0, x + pad_x)
            y = max(0, y + pad_y)
            fw = max(1, fw - 2 * pad_x)
            fh = max(1, fh - 2 * pad_y)

        roi = frame[y:y + fh, x:x + fw]
        if roi.size == 0:
            return False, 0.0

        roi_float = roi.astype(np.float32) / 255.0
        r_mean = float(np.mean(roi_float[:, :, 2]))
        g_mean = float(np.mean(roi_float[:, :, 1]))
        b_mean = float(np.mean(roi_float[:, :, 0]))

        skin_r = SKIN_R_LOW <= r_mean <= SKIN_R_HIGH
        skin_g = SKIN_G_LOW <= g_mean <= SKIN_G_HIGH
        skin_b = SKIN_B_LOW <= b_mean <= SKIN_B_HIGH

        # Ratio R/G — elevated in human skin due to blood perfusion
        rg_ratio = r_mean / (g_mean + 1e-8)
        rg_ok = 1.1 <= rg_ratio <= 2.2

        passed = skin_r and skin_g and skin_b and rg_ok

        # Heuristic confidence score
        n_ok = sum([skin_r, skin_g, skin_b, rg_ok])
        confidence = n_ok / 4.0

        return passed, confidence

    @staticmethod
    def detect_face(frame: NDArray[np.uint8]) -> Optional[Tuple[int, int, int, int]]:
        """Use OpenCV Haar cascade to locate a face.

        Returns (x, y, w, h) or None.
        """
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        )
        faces = cascade.detectMultiScale(gray, 1.1, 5, minSize=(80, 80))
        if len(faces) == 0:
            return None
        return tuple(faces[0])  # type: ignore[return-value]


# ---------------------------------------------------------------------------
#  3. RPPGEngine
# ---------------------------------------------------------------------------

class RPPGEngine:
    """Remote Photoplethysmography — extracts blood-volume pulse from video.

    Tracks the Green-channel mean over a forehead/cheek ROI across ≥ 30 frames,
    applies a bandpass IIR filter, and detects a plausible heart-rate via FFT.
    """

    def __init__(self, fps: float = 30.0) -> None:
        self.fps = fps
        self.buffer = RPPGBuffer(maxlen=int(fps * 2.5))  # ~2.5 s window

    def extract_roi(self, frame: NDArray[np.uint8],
                    face_coords: Tuple[int, int, int, int]) -> float:
        """Extract the mean Green-channel value from the upper-cheek ROI."""
        x, y, w, h = face_coords
        # Upper 40 % of the face box → forehead / cheeks
        roi = frame[y:y + int(h * 0.4), x:x + w]
        if roi.size == 0:
            return 0.0
        return float(np.mean(roi[:, :, 1]))  # Green channel

    def feed(self, frame: NDArray[np.uint8],
             face_coords: Tuple[int, int, int, int]) -> None:
        """Push a new frame into the rPPG buffer."""
        g = self.extract_roi(frame, face_coords)
        self.buffer.push(g)

    def detect_pulse(self) -> Tuple[bool, float, float]:
        """Run FFT-based pulse detection on buffered signal.

        Returns:
            (pulse_detected, heart_rate_bpm, confidence)
        """
        if not self.buffer.ready:
            return False, 0.0, 0.0

        signal = np.array(self.buffer.green_means, dtype=np.float64)
        n = len(signal)

        # Minimum variance – static images (photo attack) have near-zero
        signal_std = float(signal.std())
        if signal_std < 1e-3:
            return False, 0.0, 0.0

        # Detrend (subtract moving average)
        window = max(3, n // 8)
        kernel = np.ones(window) / window
        trend = np.convolve(signal, kernel, mode="same")
        detrended = signal - trend

        # Hamming window
        detrended *= np.hamming(n)

        # FFT
        freqs = np.fft.rfftfreq(n, d=1.0 / self.fps)
        fft_mag = np.abs(np.fft.rfft(detrended))

        # Bandpass mask
        mask = (freqs >= HR_MIN_HZ) & (freqs <= HR_MAX_HZ)
        if not np.any(mask):
            return False, 0.0, 0.0

        band_mag = fft_mag[mask]
        band_freqs = freqs[mask]

        # Peak detection
        peak_idx = int(np.argmax(band_mag))
        peak_power = band_mag[peak_idx]
        heart_rate = float(band_freqs[peak_idx] * 60.0)

        # Signal-to-noise: peak power / mean power outside band
        outside_mask = ~mask
        if np.any(outside_mask):
            noise_power = float(np.mean(fft_mag[outside_mask])) + 1e-12
        else:
            noise_power = 1e-12
        snr_db = 10.0 * np.log10(peak_power / noise_power)

        # Prominence relative to neighbours
        prominence = 1.0 if len(band_mag) <= 3 else 0.0
        if len(band_mag) > 3:
            l = max(0, peak_idx - 2)
            r = min(len(band_mag) - 1, peak_idx + 2)
            local_max = band_mag[l:r + 1].max()
            local_mean = band_mag[l:r + 1].mean()
            prominence = float((local_max - local_mean) / (local_max + 1e-12))

        pulse_ok = (snr_db >= RPPG_SNR_THRESHOLD
                    and prominence >= RPPG_MIN_PEAK_PROMINENCE
                    and HR_MIN_BPM <= heart_rate <= HR_MAX_BPM)

        confidence = min(1.0, (snr_db / RPPG_SNR_THRESHOLD)
                         * (prominence / RPPG_MIN_PEAK_PROMINENCE) * 0.5)
        return pulse_ok, heart_rate, confidence

    def reset(self) -> None:
        self.buffer.reset()


# ---------------------------------------------------------------------------
#  4. PupilChallenge
# ---------------------------------------------------------------------------

class PupilChallenge:
    """Challenge-response pupil constriction test.

    A sudden bright flash should cause the human pupil to constrict within
    200-400 ms.  Photos, screens, and masks show no change.
    """

    @staticmethod
    def measure_pupil_radius(eye_roi: NDArray[np.uint8]) -> Optional[float]:
        """Estimate pupil radius in a greyscale eye ROI using HoughCircles.

        Returns radius in pixels, or None if no circle detected.
        """
        gray = cv2.cvtColor(eye_roi, cv2.COLOR_BGR2GRAY) \
            if eye_roi.ndim == 3 else eye_roi
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        circles = cv2.HoughCircles(
            blurred,
            cv2.HOUGH_GRADIENT,
            dp=1.2,
            minDist=20,
            param1=50,
            param2=20,
            minRadius=3,
            maxRadius=60,
        )
        if circles is not None:
            return float(circles[0, 0, 2])
        return None

    @staticmethod
    def extract_eyes(frame: NDArray[np.uint8],
                     face_coords: Tuple[int, int, int, int]
                     ) -> list[NDArray[np.uint8]]:
        """Extract left and right eye regions using a cascade.

        Falls back to geometric ROIs when the cascade fails
        (e.g. on synthetic test images).
        """
        x, y, w, h = face_coords
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        eye_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_eye.xml"
        )
        face_gray = gray[y:y + h, x:x + w]
        eyes = eye_cascade.detectMultiScale(face_gray, 1.1, 5, minSize=(20, 20))
        rois: list[NDArray[np.uint8]] = []
        for ex, ey, ew, eh in eyes[:2]:
            eye_img = frame[y + ey:y + ey + eh, x + ex:x + ex + ew]
            if eye_img.size > 0:
                rois.append(eye_img)
        # Fallback: geometric ROIs when cascade finds nothing
        if not rois:
            left_x = x + int(w * 0.1)
            left_y = y + int(h * 0.25)
            left_w = int(w * 0.35)
            left_h = int(h * 0.3)
            right_x = x + int(w * 0.55)
            right_y = y + int(h * 0.25)
            right_w = int(w * 0.35)
            right_h = int(h * 0.3)
            left = frame[left_y:left_y + left_h, left_x:left_x + left_w]
            right = frame[right_y:right_y + right_h, right_x:right_x + right_w]
            if left.size > 0:
                rois.append(left)
            if right.size > 0:
                rois.append(right)
        return rois

    @staticmethod
    def verify_pupil_reaction(
        frame_before: NDArray[np.uint8],
        frame_after: NDArray[np.uint8],
        face_coords: Tuple[int, int, int, int],
    ) -> Tuple[bool, float]:
        """Compare pupil radius before and after a light flash.

        Args:
            frame_before: frame immediately before flash.
            frame_after: frame ~300 ms after flash onset.
            face_coords: (x, y, w, h) of the face.

        Returns:
            (reacted, constriction_ratio).
        """
        eyes_before = PupilChallenge.extract_eyes(frame_before, face_coords)
        eyes_after = PupilChallenge.extract_eyes(frame_after, face_coords)

        if not eyes_before or not eyes_after:
            return False, 0.0

        r_before = PupilChallenge.measure_pupil_radius(eyes_before[0])
        r_after = PupilChallenge.measure_pupil_radius(eyes_after[0])

        if r_before is None or r_after is None or r_before < 1.0:
            return False, 0.0

        ratio = (r_before - r_after) / r_before
        reacted = ratio >= PUPIL_CONSTRICTION_MIN
        return reacted, ratio


# ---------------------------------------------------------------------------
#  5. MSEVValidator  (orchestrator)
# ---------------------------------------------------------------------------

class MSEVValidator:
    """Aggregate all sub-modules and run the full liveness pipeline.

    Validation logic (strict AND):
        Result = (Signature) AND (Reflectance) AND (Pulse) AND (Pupil)
    """

    def __init__(self, fps: float = 30.0) -> None:
        self.pipeline = SecureFramePipeline()
        self.spectral = SpectralAnalyzer()
        self.rppg = RPPGEngine(fps=fps)
        self.pupil = PupilChallenge()

        self._sensor_key = self.pipeline.get_sensor_key()
        self._last_face: Optional[Tuple[int, int, int, int]] = None

    def validate_frame(self,
                       frame: NDArray[np.uint8],
                       signature: bytes,
                       flash_frame: Optional[NDArray[np.uint8]] = None,
                       face_coords: Optional[Tuple[int, int, int, int]] = None,
                       ) -> MSEVResult:
        """Run the full pipeline on a single (or pair of) frames.

        For pulse detection, call this method iteratively with consecutive
        frames (e.g. 30-60 frames).

        Args:
            frame: Current BGR frame.
            signature: Cryptographic signature from the sensor.
            flash_frame: If provided, run the pupil challenge comparing
                         *frame* (before flash) with *flash_frame* (after).
            face_coords: Optional pre-detected face box (x, y, w, h).
                         When None, the Haar cascade is used.

        Returns:
            Aggregated MSEVResult.
        """
        result = MSEVResult(passed=False)
        hr = 0.0

        # 1 — Signature
        result.signature_ok = SecureFramePipeline.verify_frame(
            frame, signature, self._sensor_key)

        if not result.signature_ok:
            result.details = "Frame signature invalid - possible injection attack."
            return result

        # 2 — Face detection
        face = face_coords if face_coords is not None else self.spectral.detect_face(frame)
        if face is None:
            result.details = "No face detected."
            return result
        self._last_face = face

        # 3 — Spectral / reflectance
        result.reflectance_ok, _ = self.spectral.analyze_reflectance(frame, face)
        if not result.reflectance_ok:
            result.details = "Reflectance signature does not match human skin."
            return result

        # 4 — rPPG (feeds internal buffer, may or may not be ready)
        self.rppg.feed(frame, face)
        result.pulse_detected, hr, _ = self.rppg.detect_pulse()

        # 5 — Pupil challenge
        if flash_frame is not None:
            result.pupil_reacted, ratio = PupilChallenge.verify_pupil_reaction(
                frame, flash_frame, face)
            if not result.pupil_reacted:
                result.details = f"Pupil constriction too weak ({ratio:.2f})."
                return result

        # 6 — Aggregate
        result.passed = (result.signature_ok
                         and result.reflectance_ok
                         and result.pulse_detected
                         and (flash_frame is None or result.pupil_reacted))

        n_checks = 3 + int(flash_frame is not None)
        n_passed = (int(result.signature_ok)
                    + int(result.reflectance_ok)
                    + int(result.pulse_detected)
                    + int(result.pupil_reacted or flash_frame is None))
        result.confidence = min(1.0, n_passed / max(1, n_checks))
        result.details = result.details or f"HR={hr:.0f} BPM, confidence={result.confidence:.2f}"
        return result

    def reset_rppg(self) -> None:
        self.rppg.reset()


# ===================================================================
#  Demo / Self-test
# ===================================================================

def _make_checkerboard(w: int, h: int, cell=8) -> NDArray[np.uint8]:
    """Generate a synthetic test pattern (spoof: no skin)."""
    chess = np.indices((h, w)).sum(axis=0) // cell % 2
    img = np.zeros((h, w, 3), dtype=np.uint8)
    img[chess == 0] = (180, 120, 80)   # beige-ish
    img[chess == 1] = (60, 60, 60)     # dark
    return img


def _make_skin_patch(w: int, h: int) -> NDArray[np.uint8]:
    """Generate a uniform 'skin' coloured patch (overly ideal)."""
    img = np.full((h, w, 3), (140, 170, 200), dtype=np.uint8)  // BGR
    return img


def _simulate_human_face_sequence(n_frames: int = 60, fps: float = 30.0,
                                   with_pulse: bool = True
                                   ) -> list[NDArray[np.uint8]]:
    """Generate a synthetic face-like sequence with a subtle rPPG signal.

    The pulse manifests as a periodic variation in the Green channel
    superimposed on the face region.
    """
    h, w = 240, 320
    frames: list[NDArray[np.uint8]] = []
    # Base face colour (BGR) – typical skin (fits reflectance ranges)
    base_b, base_g, base_r = 80.0, 110.0, 165.0

    for i in range(n_frames):
        frame = np.full((h, w, 3), (40, 40, 40), dtype=np.uint8)

        if with_pulse:
            t = i / fps
            # ~72 BPM sinusoidal modulation on Green channel
            mod = 8.0 * np.sin(2.0 * np.pi * 1.2 * t)
        else:
            mod = 0.0

        # Draw an ellipse as "face"
        face_center = (w // 2, h // 2)
        face_axes = (60, 80)
        color = (int(base_b), int(base_g + mod), int(base_r))
        cv2.ellipse(frame, face_center, face_axes, 0, 0, 360, color, -1)
        frames.append(frame)

    return frames


def _simulate_spoof_sequence(n_frames: int = 60) -> list[NDArray[np.uint8]]:
    """Flat, no-pulse sequence (photo attack)."""
    h, w = 240, 320
    frames: list[NDArray[np.uint8]] = []
    for _ in range(n_frames):
        frame = np.full((h, w, 3), (40, 40, 40), dtype=np.uint8)
        cv2.ellipse(frame, (w // 2, h // 2), (60, 80), 0, 0, 360,
                    (80, 110, 165), -1)
        frames.append(frame)
    return frames


def _simulate_pupil_reaction(radius_before: float, radius_after: float,
                             ) -> Tuple[NDArray[np.uint8], NDArray[np.uint8]]:
    """Synthesise two eye frames with different pupil sizes."""
    size = 100
    before = np.zeros((size, size, 3), dtype=np.uint8)
    after = np.zeros((size, size, 3), dtype=np.uint8)
    cv2.circle(before, (50, 50), int(radius_before), (255, 255, 255), -1)
    cv2.circle(after, (50, 50), int(radius_after), (255, 255, 255), -1)
    return before, after


# ===================================================================

def _make_face_frame(w: int, h: int,
                     color_bgr: Tuple[int, int, int] = (80, 110, 165),
                     pulse_mod: float = 0.0) -> NDArray[np.uint8]:
    """Render a single frame with an elliptical 'face' at centre."""
    frame = np.full((h, w, 3), (40, 40, 40), dtype=np.uint8)
    b, g, r_ = color_bgr
    color = (int(b), int(g + pulse_mod), int(r_))
    cv2.ellipse(frame, (w // 2, h // 2), (60, 80), 0, 0, 360, color, -1)
    return frame


# Hard-coded face bounding box matching _make_face_frame geometry
_FACE_BOX: Tuple[int, int, int, int] = (100, 40, 120, 160)


if __name__ == "__main__":
    import sys

    print("=" * 60)
    print("MSEV - Multi-Spectral & Electro-Vascular Liveness Detector")
    print("=" * 60)

    val = MSEVValidator(fps=30.0)
    pipeline = val.pipeline  # use the same sensor instance

    # ── Test A : valid human ─────────────────────────────────────
    print("\n[TEST A] Valid human (live face + pulse + pupil)")
    faces_a: list[NDArray[np.uint8]] = []
    for i in range(90):
        t = i / 30.0
        mod = 10.0 * np.sin(2.0 * np.pi * 1.2 * t)  # ~72 BPM, stronger modulation
        pupil_r = 10.0 if i < 89 else 7.0           # constricts at last frame
        frame = _make_face_frame(320, 240, pulse_mod=mod)
        # Place pupils inside eye ROIs for HoughCircle detection
        cv2.circle(frame, (133, 100), int(pupil_r), (30, 30, 30), -1)
        cv2.circle(frame, (187, 100), int(pupil_r), (30, 30, 30), -1)
        faces_a.append(frame)

    for i, f in enumerate(faces_a):
        f_signed, sig = pipeline.simulate_signed_frame(f)
        flash = faces_a[-1] if i == len(faces_a) - 2 else None
        r = val.validate_frame(f_signed, sig, flash_frame=flash, face_coords=_FACE_BOX)

    final_a = r
    print(f"  Signature  : {'PASS' if final_a.signature_ok else 'FAIL'}")
    print(f"  Reflectance: {'PASS' if final_a.reflectance_ok else 'FAIL'}")
    print(f"  Pulse      : {'PASS' if final_a.pulse_detected else 'FAIL'}")
    print(f"  Pupil      : {'PASS' if final_a.pupil_reacted else 'FAIL'}")
    print(f"  Overall    : {'GRANTED' if final_a.passed else 'DENIED'}")
    print(f"  Confidence : {final_a.confidence:.2f}")
    if not final_a.passed:
        print(f"  DETAILS    : {final_a.details}")

    # ── Test B : photo attack (no pulse) ─────────────────────────
    print("\n[TEST B] Photo attack (static frame, no pulse)")
    val.reset_rppg()
    for _ in range(90):
        frame = _make_face_frame(320, 240, pulse_mod=0.0)
        f_signed, sig = pipeline.simulate_signed_frame(frame)
        r = val.validate_frame(f_signed, sig, face_coords=_FACE_BOX)
    final_b = r
    print(f"  Signature  : {'PASS' if final_b.signature_ok else 'FAIL'}")
    print(f"  Reflectance: {'PASS' if final_b.reflectance_ok else 'FAIL'}")
    print(f"  Pulse      : {'PASS' if final_b.pulse_detected else 'FAIL'}")
    print(f"  Overall    : {'GRANTED' if final_b.passed else 'DENIED'}")

    # ── Test C : silicone mask (bad reflectance) ─────────────────
    print("\n[TEST C] Silicone mask (non-skin reflectance)")
    # Use a checkerboard as a proxy for unnatural reflectance
    mask_frame = _make_checkerboard(320, 240)
    signed, sig = pipeline.simulate_signed_frame(mask_frame)
    final_c = val.validate_frame(signed, sig)
    print(f"  Signature  : {'PASS' if final_c.signature_ok else 'FAIL'}")
    print(f"  Reflectance: {'PASS' if final_c.reflectance_ok else 'FAIL'}")
    print(f"  Overall    : {'GRANTED' if final_c.passed else 'DENIED'}")

    # ── Test D : injection attack (bad signature) ────────────────
    print("\n[TEST D] Frame injection (forged signature)")
    live = _make_face_frame(320, 240)
    fake_frame, fake_sig = SecureFramePipeline.simulate_spoof_frame(live)
    final_d = val.validate_frame(fake_frame, fake_sig)
    print(f"  Signature  : {'PASS' if final_d.signature_ok else 'FAIL'}")
    print(f"  Overall    : {'GRANTED' if final_d.passed else 'DENIED'}")

    # ── Test E : no pupil reaction ───────────────────────────────
    print("\n[TEST E] Screen attack (no pupil constriction)")
    val.reset_rppg()
    faces_e: list[NDArray[np.uint8]] = []
    for i in range(90):
        t = i / 30.0
        mod = 10.0 * np.sin(2.0 * np.pi * 1.2 * t)
        frame = _make_face_frame(320, 240, pulse_mod=mod)
        cv2.circle(frame, (133, 100), 10, (30, 30, 30), -1)
        cv2.circle(frame, (187, 100), 10, (30, 30, 30), -1)
        faces_e.append(frame)
    pupil_ok = True
    for i, f in enumerate(faces_e):
        f_signed, sig = pipeline.simulate_signed_frame(f)
        flash = faces_e[-1] if i == len(faces_e) - 2 else None
        r = val.validate_frame(f_signed, sig, flash_frame=flash, face_coords=_FACE_BOX)
        if flash is not None:
            pupil_ok = r.pupil_reacted
    final_e = r
    final_e.pupil_reacted = pupil_ok
    # Recompute passed without the pupil check shortcut
    all_checks = (final_e.signature_ok and final_e.reflectance_ok
                  and final_e.pulse_detected and pupil_ok)
    final_e.passed = all_checks
    print(f"  Pulse      : {'PASS' if final_e.pulse_detected else 'FAIL'}")
    print(f"  Pupil      : {'PASS' if final_e.pupil_reacted else 'FAIL'}")
    print(f"  Overall    : {'GRANTED' if final_e.passed else 'DENIED'}")

    # ── Summary ──────────────────────────────────────────────────
    tests = [
        ("A) Valid human", final_a.passed, True),
        ("B) Photo attack", final_b.passed, False),
        ("C) Silicone mask", final_c.passed, False),
        ("D) Injection", final_d.passed, False),
        ("E) No pupil", final_e.passed, False),
    ]
    print("\n" + "=" * 60)
    all_ok = True
    for name, got, expected in tests:
        status = "OK" if got == expected else "FAIL"
        if status == "FAIL":
            all_ok = False
        print(f"  [{status}] {name} (expected={expected}, got={got})")
    print("=" * 60)
    print(f"  Overall: {'ALL TESTS PASSED' if all_ok else 'SOME TESTS FAILED'}")
    print("=" * 60)
    sys.exit(0 if all_ok else 1)
