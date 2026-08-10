export function parseServerTiming(value) {
  if (!value) return null;
  const metric = (name) => {
    const match = value.match(new RegExp(`(?:^|,\\s*)${name};dur=([0-9.]+)`));
    return match ? Number(match[1]) : null;
  };
  const roundTrips = value.match(/sabledb;dur=[0-9.]+;desc="([0-9]+) round trips"/);
  const app = metric("app");
  const sabledb = metric("sabledb");
  const nonstore = metric("nonstore");
  if (app === null || sabledb === null || nonstore === null || !roundTrips) return null;
  return { app, sabledb, nonstore, roundTrips: Number(roundTrips[1]) };
}
