import catalogue from "../../../../benchmarks/catalog.json";
import type { APIRoute } from "astro";

export const GET: APIRoute = () =>
  new Response(JSON.stringify(catalogue, null, 2), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "public, max-age=300, s-maxage=3600",
      "X-Content-Type-Options": "nosniff",
    },
  });
