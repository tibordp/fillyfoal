import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // Served from wherever it's put: every URL is relative.
  base: "./",
  plugins: [react()],
  worker: { format: "es" },
  build: { target: "es2022" },
});
