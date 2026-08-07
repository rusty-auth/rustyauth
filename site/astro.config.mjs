import { defineConfig } from "astro/config";
import solid from "@astrojs/solid-js";

export default defineConfig({
  site: "https://rustyauth.dev",
  output: "static",
  integrations: [solid()],
  vite: {
    build: {
      // Three.js is isolated in the single interactive hero island. The
      // minified engine chunk is intentionally larger than Vite's generic
      // application default and remains cacheable across every static route.
      chunkSizeWarningLimit: 650,
    },
    ssr: {
      noExternal: true,
    },
    server: {
      host: "0.0.0.0",
      allowedHosts: ["terminal.local"],
    },
  },
});
