import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

export default defineConfig({
  plugins: [solid()],
  publicDir: "../site/public",
  resolve: {
    alias: {
      "@rustyauth/connect-solid": new URL("../packages/connect-solid/src/index.ts", import.meta.url).pathname,
      "@rustyauth/protocol": new URL("../packages/protocol/index.ts", import.meta.url).pathname,
    },
  },
  server: {
    host: "127.0.0.1",
    port: 5174,
    strictPort: true,
    allowedHosts: ["terminal.local"],
    proxy: {
      "/v1": "http://127.0.0.1:8081",
      "/.well-known": "http://127.0.0.1:8081",
      "/rustyauth.events.v1": "http://127.0.0.1:8081",
      "/rustyauth.identity.v1": "http://127.0.0.1:8081",
      "/rustyauth.organization.v1": "http://127.0.0.1:8081",
      "/rustyauth.service_accounts.v1": "http://127.0.0.1:8081",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
