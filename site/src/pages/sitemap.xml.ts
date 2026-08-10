import type { APIRoute } from "astro";
import { docsItems } from "../data/docs";
import { guides } from "../data/guides";
import { solutions } from "../data/solutions";

const canonicalPath = (pathname: string) => pathname === "/" ? "/" : `${pathname.replace(/\/+$/, "")}/`;

const escapeXml = (value: string) =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");

export const GET: APIRoute = ({ site }) => {
  if (!site) throw new Error("Astro.site must be configured to build the sitemap");

  const routes = [
    "/",
    "/why-rustyauth",
    "/fleet",
    "/benchmarks",
    "/guides",
    "/solutions",
    ...solutions.map((solution) => `/solutions/${solution.slug}`),
    ...docsItems.map((item) => item.href),
    ...guides.map((guide) => guide.href),
  ];
  const urls = [...new Set(routes)]
    .map((route) => new URL(canonicalPath(route), site).href)
    .sort();
  const body = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ...urls.map((url) => `  <url><loc>${escapeXml(url)}</loc></url>`),
    "</urlset>",
  ].join("\n");

  return new Response(body, {
    headers: {
      "Content-Type": "application/xml; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
    },
  });
};
