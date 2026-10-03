import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

const savedTheme = localStorage.getItem("soc_theme");
if (savedTheme) {
  document.documentElement.setAttribute("data-theme", savedTheme);
} else {
  document.documentElement.setAttribute("data-theme", "soc-dark");
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
