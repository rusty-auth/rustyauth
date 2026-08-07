import { createSignal, onMount } from "solid-js";

const compact = (count: number) =>
  new Intl.NumberFormat("en", { notation: count >= 1000 ? "compact" : "standard", maximumFractionDigits: 1 })
    .format(count);

export default function GitHubStars() {
  const [stars, setStars] = createSignal<number | null>(null);

  onMount(async () => {
    try {
      const response = await fetch("https://api.github.com/repos/rusty-auth/rustyauth", {
        headers: { Accept: "application/vnd.github+json" },
      });
      if (!response.ok) return;
      const repository = await response.json() as { stargazers_count?: number };
      if (typeof repository.stargazers_count === "number") setStars(repository.stargazers_count);
    } catch {
      // The link remains useful when GitHub is unavailable or rate limited.
    }
  });

  return (
    <a
      class="github-proof"
      href="https://github.com/rusty-auth/rustyauth"
      aria-label={stars() === null ? "View RustyAuth on GitHub" : `RustyAuth has ${stars()} GitHub stars`}
    >
      <span>GitHub</span>
      <b>{stars() === null ? "Stars" : `${compact(stars()!)} stars`}</b>
    </a>
  );
}
