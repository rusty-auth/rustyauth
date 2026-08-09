export interface Guide {
  label: string;
  href: string;
  description: string;
  eyebrow: string;
}

export const guides: Guide[] = [
  {
    label: "Passkey authentication",
    href: "/passkey-authentication",
    description: "Understand WebAuthn registration, sign-in and origin binding.",
    eyebrow: "WebAuthn",
  },
  {
    label: "Self-hosted authentication",
    href: "/self-hosted-authentication",
    description: "Compare deployment models, operational ownership and tradeoffs.",
    eyebrow: "Deployment",
  },
  {
    label: "Authentication in Rust",
    href: "/authentication-in-rust",
    description: "Design a small, fast identity boundary with Rust and SableDB.",
    eyebrow: "Rust architecture",
  },
  {
    label: "Authentication events",
    href: "/authentication-events",
    description: "Connect signups and identity changes through gRPC streams, polling or signed webhooks.",
    eyebrow: "Events and integration",
  },
];
