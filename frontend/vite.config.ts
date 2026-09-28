import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The UI is served by `kasauti serve` from the same origin as the API (backend/kasauti/api/app.py),
// under a policy that allows no inline script or style. In development, Vite proxies /api to it:
// the Host header is kept (no changeOrigin), so the server's host and cross-site checks see the
// page's own origin, exactly as in production.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: { "/api": { target: "http://127.0.0.1:8000" } },
  },
  build: {
    // No inline <script> or data: module: everything a page runs is a file the CSP allows.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
    target: "es2022",
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
