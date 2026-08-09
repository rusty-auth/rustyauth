import { dirname, join, normalize, relative } from "node:path";

const repositoryRoot = Deno.cwd();
const skippedDirectories = new Set([".claude", ".git", ".deno", "dist", "node_modules", "target"]);

async function* markdownFiles(directory: string): AsyncGenerator<string> {
  for await (const entry of Deno.readDir(directory)) {
    const fullPath = join(directory, entry.name);
    const repositoryPath = relative(repositoryRoot, fullPath);
    if (entry.isDirectory) {
      if (skippedDirectories.has(entry.name) || repositoryPath === "docs/business") continue;
      yield* markdownFiles(fullPath);
    } else if (entry.isFile && entry.name.toLowerCase().endsWith(".md")) {
      yield fullPath;
    }
  }
}

function localDestination(rawDestination: string): string | undefined {
  let destination = rawDestination.trim();
  if (destination.startsWith("<")) {
    const closing = destination.indexOf(">");
    if (closing === -1) return undefined;
    destination = destination.slice(1, closing);
  } else {
    destination = destination.split(/\s+["']/u, 1)[0];
  }
  if (
    !destination || destination.startsWith("#") || destination.startsWith("/") ||
    /^[a-z][a-z0-9+.-]*:/iu.test(destination)
  ) return undefined;
  return decodeURIComponent(destination.split(/[?#]/u, 1)[0]).replaceAll("\\ ", " ");
}

const failures: string[] = [];
for await (const file of markdownFiles(repositoryRoot)) {
  const source = await Deno.readTextFile(file);
  const linkPattern = /!?\[[^\]]*\]\(([^)]+)\)/gu;
  for (const match of source.matchAll(linkPattern)) {
    const destination = localDestination(match[1]);
    if (!destination) continue;
    const resolved = normalize(join(dirname(file), destination));
    try {
      await Deno.stat(resolved);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
      const line = source.slice(0, match.index).split("\n").length;
      failures.push(`${relative(repositoryRoot, file)}:${line} -> ${destination}`);
    }
  }
}

if (failures.length) {
  console.error("Broken local documentation links:\n" + failures.map((failure) => `  ${failure}`).join("\n"));
  Deno.exit(1);
}

console.log("Documentation links are valid.");
