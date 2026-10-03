import { useState, useEffect } from "react";

const WORD = "welcom";
const TYPE_MS = 160;
const HOLD_MS = 650;
const FADE_MS = 450;

export default function SplashScreen({ onDone }) {
  const [typed, setTyped] = useState("");
  const [fading, setFading] = useState(false);

  useEffect(() => {
    let idx = 0;
    let typeTimer = null;
    let holdTimer = null;
    let fadeTimer = null;

    typeTimer = setInterval(() => {
      idx += 1;
      setTyped(WORD.slice(0, idx));
      if (idx >= WORD.length) {
        clearInterval(typeTimer);
        holdTimer = setTimeout(() => {
          setFading(true);
          fadeTimer = setTimeout(() => onDone(), FADE_MS);
        }, HOLD_MS);
      }
    }, TYPE_MS);

    return () => {
      clearInterval(typeTimer);
      clearTimeout(holdTimer);
      clearTimeout(fadeTimer);
    };
  }, [onDone]);

  return (
    <div className={`splash-screen ${fading ? "splash-fade-out" : ""}`}>
      <div className="splash-bg">
        <div className="splash-gradient" />
        <div className="splash-scanlines" />
        <div className="splash-radar" />
        <div className="splash-vignette" />
      </div>

      <div className="splash-content">
        <div className="splash-word-wrap">
          <h1 className="splash-word" aria-label="hello">
            {WORD.split("").map((ch, i) => (
              <span
                key={i}
                className={`splash-char ${i < typed.length ? "visible" : ""} ${i === typed.length - 1 ? "caret" : ""}`}
                style={{ transitionDelay: `${i * 10}ms` }}
              >
                {ch}
              </span>
            ))}
            <span className={`splash-cursor ${typed.length === WORD.length ? "blink" : ""}`} aria-hidden>
              _
            </span>
          </h1>
          <div className="splash-underline">
            <div className="splash-underline-fill" style={{ width: `${(typed.length / WORD.length) * 100}%` }} />
          </div>
        </div>

        <div className="splash-meta">
          <span className="splash-meta-dot" />
          <span className="splash-meta-text">SENTINEL BRIDGE // SECURE CHANNEL</span>
          <span className="splash-meta-dot" />
        </div>

        <div className="splash-loader">
          <div className="splash-loader-track">
            <div className="splash-loader-fill" style={{ width: `${(typed.length / WORD.length) * 100}%` }} />
          </div>
          <span className="splash-loader-label">INIT</span>
        </div>
      </div>

      <div className="splash-hud splash-hud-tl" />
      <div className="splash-hud splash-hud-tr" />
      <div className="splash-hud splash-hud-bl" />
      <div className="splash-hud splash-hud-br" />
    </div>
  );
}
