import { defineConfig } from "astro/config";
import solid from "@astrojs/solid-js";

export default defineConfig({
  site: "https://rustyauth.dev",
  output: "static",
  integrations: [solid()],
  vite: {
    ssr: {
      noExternal: true,
    },
    server: {
      host: "0.0.0.0",
      allowedHosts: ["terminal.local"],
    },
  },
});
