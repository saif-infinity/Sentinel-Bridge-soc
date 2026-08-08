import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ["react", "react-dom"],
          router: ["react-router-dom"],
          query: ["@tanstack/react-query"],
          charts: ["recharts"],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/devices": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true
      },
      "/logs": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true
      },
      "/ws": { 
        target: "ws://127.0.0.1:8000", 
        ws: true
      },
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true
      },
      "/auth": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true
      }
    }
  }
});