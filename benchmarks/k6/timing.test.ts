import { assertEquals } from "@std/assert";
import { parseServerTiming } from "./timing.js";

Deno.test("parses the authenticated API and SableDB timing waterfall", () => {
  assertEquals(
    parseServerTiming('app;dur=12.345, sabledb;dur=4.250;desc="3 round trips", nonstore;dur=8.095'),
    { app: 12.345, sabledb: 4.25, nonstore: 8.095, roundTrips: 3 },
  );
  assertEquals(parseServerTiming(""), null);
  assertEquals(parseServerTiming("app;dur=12.345"), null);
});
