const config = await Deno.readTextFile("console/Dioxus.toml");
const manifest = await Deno.readTextFile("console/Cargo.toml");
const main = await Deno.readTextFile("console/src/main.rs");
const workflow = await Deno.readTextFile(".github/workflows/native-packaging.yml");

const requiredConfig = [
  "[bundle]",
  'identifier = "dev.rustyauth.console"',
  'publisher = "RustyAuth"',
  "hardened_runtime = true",
  'digest_algorithm = "sha-256"',
  "tsp = true",
];
const missingConfig = requiredConfig.filter((value) => !config.includes(value));
const requiredWorkflow = [
  "name: Native preview qualification",
  "macos-14",
  "windows-2025",
  "ubuntu-24.04",
  "package_type: macos",
  "package_type: msi",
  "package_type: deb",
  "preview-unsigned",
  "if-no-files-found: error",
  "retention-days: 7",
  "push:",
  "branches: [main]",
  "schedule:",
];
const missingWorkflow = requiredWorkflow.filter((value) => !workflow.includes(value));

if (missingConfig.length || missingWorkflow.length) {
  if (missingConfig.length) {
    console.error(`Native bundle configuration is missing: ${missingConfig.join(", ")}`);
  }
  if (missingWorkflow.length) {
    console.error(`Native packaging workflow is missing: ${missingWorkflow.join(", ")}`);
  }
  Deno.exit(1);
}

if (!manifest.includes("bundle = []") || !main.includes('windows_subsystem = "windows"')) {
  console.error("Native bundle feature must suppress the Windows console without affecting development");
  Deno.exit(1);
}

if (config.includes("signing_identity") || config.includes("certificate_thumbprint")) {
  console.error("Publisher identities must be injected by release infrastructure, not committed");
  Deno.exit(1);
}

if (workflow.includes('tags: ["v*"]')) {
  console.error("Unsigned native preview packages must not run on or block GA release tags");
  Deno.exit(1);
}

console.log(
  "Native preview policy covers asynchronous main/scheduled unsigned macOS, Windows, and Linux packages without coupling them to GA tags.",
);
