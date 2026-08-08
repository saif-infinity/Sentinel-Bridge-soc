import { useState, useCallback } from "react";
import translations from "./translations";

let globalLang = localStorage.getItem("lang") || "fr";
let globalSetLang = null;

export function getLanguage() {
  return globalLang;
}

export function setLanguage(lang) {
  globalLang = lang;
  localStorage.setItem("lang", lang);
  if (globalSetLang) globalSetLang(lang);
}

export function t(key) {
  return translations[globalLang]?.[key] || translations.en[key] || key;
}

export function useTranslation() {
  const [lang, _setLang] = useState(globalLang);
  globalSetLang = _setLang;

  const switchLang = useCallback((newLang) => {
    setLanguage(newLang);
  }, []);

  return { lang, t, switchLang };
}
