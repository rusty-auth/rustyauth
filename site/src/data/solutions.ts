export interface Solution {
  slug: string;
  sector: string;
  shortTitle: string;
  cardBody: string;
  eyebrow: string;
  headline: string;
  intro: string;
  scenarioTitle: string;
  scenario: string;
  pressures: Array<[string, string]>;
  capabilities: Array<[string, string]>;
  boundary: Array<[string, string, string]>;
  doesNotReplace: string[];
  productionNeeds: string[];
}

export const solutions: Solution[] = [
  {
    slug: "saas",
    sector: "SaaS",
    shortTitle: "Ship secure sign-in without becoming an identity company.",
    cardBody:
      "Add a compact passkey boundary to your product while keeping customer identity state in infrastructure you control.",
    eyebrow: "For SaaS product teams",
    headline: "Authentication that moves at product speed.",
    intro:
      "RustyAuth packages WebAuthn ceremonies, durable sessions, token issuance and key operations behind one narrow service boundary.",
    scenarioTitle: "A product team preparing for its next stage of growth",
    scenario:
      "The team wants phishing-resistant sign-in now, but does not want authentication logic spread across the application or customer identity locked into a mandatory hosted provider. It starts with a local deployment, integrates through explicit HTTP and gRPC contracts, and keeps the option to run the same boundary in customer-controlled infrastructure later.",
    pressures: [
      [
        "Ship without the auth detour",
        "Avoid assembling ceremonies, cookie policy, token signing and credential lifecycle code across the product.",
      ],
      [
        "Reduce reusable secrets",
        "Give people a passkey-first path instead of making passwords the permanent centre of the account model.",
      ],
      [
        "Preserve deployment choice",
        "Keep a route from a normal cloud deployment to customer cloud, on-premises or isolated installations.",
      ],
    ],
    capabilities: [
      [
        "Passkey ceremonies",
        "Server-side, five-minute and single-use registration and authentication state.",
      ],
      ["Revocable sessions", "HttpOnly browser sessions with idle and absolute expiry."],
      ["Narrow tokens", "Short-lived ES256 access tokens with explicit issuer, audience and tenant claims."],
    ],
    boundary: [
      ["01", "Product browser", "Creates and uses a passkey"],
      ["02", "RustyAuth", "Verifies ceremonies and owns sessions"],
      ["03", "Private SableDB", "Keeps durable identity state"],
      ["04", "Application API", "Validates claims and applies policy"],
    ],
    doesNotReplace: [
      "Application roles and entitlements",
      "Billing or subscription policy",
      "Customer support and recovery policy",
    ],
    productionNeeds: [
      "Account recovery and abuse controls",
      "Stable migration policy",
      "Independent security assessment",
    ],
  },
  {
    slug: "gambling-gaming",
    sector: "Gambling and gaming",
    shortTitle: "Protect player and operator access at internet scale.",
    cardBody:
      "Use phishing-resistant authentication as one layer in an account-security programme built for high-value, heavily targeted platforms.",
    eyebrow: "For gambling and gaming platforms",
    headline: "Make account takeover harder—not play harder.",
    intro:
      "A passkey-first identity boundary can protect player and operator access without pretending authentication alone solves fraud or regulation.",
    scenarioTitle: "A regulated platform protecting player and operator accounts",
    scenario:
      "Credential stuffing, phishing and support-channel manipulation put both customer balances and operator tools at risk. The platform introduces passkeys for sign-in and designs dedicated reauthentication for sensitive account changes, while its existing risk, payments and responsible-gaming systems remain authoritative.",
    pressures: [
      [
        "Account takeover",
        "Reusable credentials are repeatedly targeted because an account can contain identity data, balances and payment access.",
      ],
      [
        "Conversion sensitivity",
        "Security has to fit a fast customer journey instead of introducing a new password or code at every visit.",
      ],
      [
        "Privileged operations",
        "Support and operator access needs a stronger boundary than a broad staff password and a long-lived session.",
      ],
    ],
    capabilities: [
      ["Passkey-first access", "Phishing-resistant WebAuthn registration and authentication."],
      ["Session control", "Server-side expiry and revocation rather than browser-only bearer state."],
      ["Ordered events", "A resumable event stream for downstream operational integrations."],
    ],
    boundary: [
      ["01", "Player or operator", "Uses an enrolled passkey"],
      ["02", "Gaming product", "Owns the customer journey"],
      ["03", "RustyAuth", "Authenticates and issues narrow claims"],
      ["04", "Risk and payments", "Make fraud and transaction decisions"],
    ],
    doesNotReplace: [
      "Age or identity verification",
      "KYC, AML or payment controls",
      "Fraud, bot or bonus-abuse detection",
      "Responsible-gaming and self-exclusion systems",
    ],
    productionNeeds: [
      "Abuse-resistant recovery",
      "Risk-based step-up ceremonies",
      "Multi-brand tenancy and high availability",
      "Decision-grade audit export",
    ],
  },
  {
    slug: "banking-payments",
    sector: "Banking and payments",
    shortTitle: "Keep sensitive access inside the institution’s control.",
    cardBody:
      "Protect customer and workforce sign-in with a boundary designed for private infrastructure, short-lived trust and immediate revocation.",
    eyebrow: "For banking and payment systems",
    headline: "Customer-controlled authentication for sensitive access.",
    intro:
      "RustyAuth can become a compact authentication component beside a banking product—not a claim to replace the institution’s identity, fraud or transaction controls.",
    scenarioTitle: "A banking software provider protecting a sensitive workflow",
    scenario:
      "The provider needs phishing-resistant customer or workforce access while preserving the bank’s control over identity state, signing keys and operational recovery. RustyAuth sits inside the institution’s environment and issues short-lived claims to the application, while the bank’s policy and risk systems decide what each authenticated person may do.",
    pressures: [
      [
        "Operational resilience",
        "Authentication should not become unavailable solely because a public identity service or external network path is down.",
      ],
      [
        "Credential risk",
        "Phishing-resistant credentials reduce reliance on passwords and manually entered one-time codes.",
      ],
      [
        "Institutional control",
        "Keys, audit evidence, recovery and deployment lifecycle must fit established governance boundaries.",
      ],
    ],
    capabilities: [
      ["Local verification", "WebAuthn ceremonies are verified inside the deployed RustyAuth boundary."],
      ["Short-lived claims", "Audience-bound access tokens narrow the trust passed to banking applications."],
      ["Key lifecycle", "Staged signing-key rotation with overlapping public-key publication."],
    ],
    boundary: [
      ["01", "Customer or employee", "Authenticates with a passkey"],
      ["02", "RustyAuth", "Maintains the authenticated session"],
      ["03", "Banking application", "Consumes narrow identity claims"],
      ["04", "Bank controls", "Apply policy, risk and transaction rules"],
    ],
    doesNotReplace: [
      "Transaction signing or payment approval",
      "Fraud and risk engines",
      "KYC or AML controls",
      "Core banking authorisation",
    ],
    productionNeeds: [
      "HSM-backed server keys",
      "Qualified high availability",
      "Dual-control administration",
      "Enterprise federation and independent assessment",
    ],
  },
  {
    slug: "financial-services",
    sector: "Financial services",
    shortTitle: "Narrow identity trust across financial software.",
    cardBody:
      "Give fintech, trading, wealth and insurance products a portable authentication boundary without conflating identity with business authority.",
    eyebrow: "For financial software",
    headline: "A smaller trust boundary for high-consequence products.",
    intro:
      "Financial applications can keep authentication compact, auditable and deployable while their own systems remain responsible for portfolios, trades and entitlements.",
    scenarioTitle: "A financial platform serving regulated organisations",
    scenario:
      "The platform needs a consistent sign-in boundary across its standard SaaS deployment and private customer environments. RustyAuth authenticates users and issues narrowly scoped identity claims; the financial platform continues to own account relationships, suitability, permissions and every business decision.",
    pressures: [
      [
        "Mixed deployment estate",
        "One product may need to run in the vendor cloud, a customer VPC and a tightly controlled on-premises environment.",
      ],
      [
        "High-consequence access",
        "A stolen session can expose sensitive data or create a path towards valuable operations.",
      ],
      [
        "Audit expectations",
        "Identity events need to feed the organisation’s wider evidence, monitoring and incident-response systems.",
      ],
    ],
    capabilities: [
      ["Portable boundary", "A small Rust service and private persistence topology."],
      ["Revocable access", "Durable sessions and independently revocable service credentials."],
      ["Recovery operations", "Encrypted logical backups with verification and clean-room restore commands."],
    ],
    boundary: [
      ["01", "User", "Proves control of a passkey"],
      ["02", "RustyAuth", "Authenticates and records events"],
      ["03", "Financial product", "Applies roles and entitlements"],
      ["04", "Systems of record", "Remain authoritative for assets and actions"],
    ],
    doesNotReplace: [
      "Portfolio or trading permissions",
      "Suitability and compliance workflows",
      "Fraud and financial-crime controls",
      "Business systems of record",
    ],
    productionNeeds: [
      "High availability and workload identity",
      "SIEM and evidence export",
      "Enterprise federation",
      "Abuse-resistant recovery",
    ],
  },
  {
    slug: "healthcare-products",
    sector: "Healthcare products",
    shortTitle: "Authentication that can ship with the product.",
    cardBody:
      "Embed a local identity boundary into diagnostic platforms, clinical appliances and software deployed inside controlled healthcare networks.",
    eyebrow: "For healthcare product teams",
    headline: "Secure sign-in where the product is actually used.",
    intro:
      "Healthcare products often operate inside customer networks where external dependencies are restricted, unreliable or governed by the provider.",
    scenarioTitle: "A diagnostic platform installed inside hospital networks",
    scenario:
      "Clinicians and service engineers need reliable access even when the hospital does not permit the product to depend on an external identity service. RustyAuth travels with the product, keeps identity state private to the installation and issues local claims to the diagnostic application.",
    pressures: [
      [
        "Restricted connectivity",
        "Hospital network policy may limit outbound access or require the product to remain useful during external outages.",
      ],
      [
        "Product lifecycle",
        "Authentication has to be installed, upgraded, backed up and recovered alongside the product it protects.",
      ],
      [
        "Distinct user duties",
        "Clinical, service and administrative responsibilities must remain explicit in the application’s own policy layer.",
      ],
    ],
    capabilities: [
      [
        "Local operation",
        "Authentication and durable identity state remain within the installed environment.",
      ],
      [
        "Multiple credentials",
        "Accounts can enrol labelled passkeys and protect the final credential from accidental removal.",
      ],
      [
        "Private integration",
        "Typed identity reads and mutations are available across a private service boundary.",
      ],
    ],
    boundary: [
      ["01", "Clinician or engineer", "Uses an approved authenticator"],
      ["02", "Healthcare product", "Owns the workflow and user experience"],
      ["03", "Local RustyAuth", "Authenticates inside the installation"],
      ["04", "Clinical systems", "Retain domain authority and records"],
    ],
    doesNotReplace: [
      "Patient identity matching",
      "Clinical authorisation policy",
      "Medical-device safety controls",
      "Regulatory validation or compliance evidence",
    ],
    productionNeeds: [
      "Offline update and support lifecycle",
      "Qualified recovery and high availability",
      "Authenticator policy and attestation",
      "Independent product-security assessment",
    ],
  },
  {
    slug: "defence-secure-systems",
    sector: "Defence and secure systems",
    shortTitle: "Modern authentication inside a disconnected boundary.",
    cardBody:
      "Bring phishing-resistant access to secure engineering tools, deployable systems and isolated enclaves without a mandatory public-cloud dependency.",
    eyebrow: "For defence and secure systems",
    headline: "Passkey authentication that stays inside the boundary.",
    intro:
      "A future assured RustyAuth profile could operate with local trust, device-bound authenticators and an entirely offline software lifecycle.",
    scenarioTitle: "An engineering application operating in a disconnected enclave",
    scenario:
      "Personnel authenticate with organisation-issued, device-bound security keys. RustyAuth verifies every ceremony against local state, creates a revocable session and issues a short-lived token to the protected application. DNS, certificates, time, backups and operational evidence all remain inside the enclave.",
    pressures: [
      [
        "No public dependency",
        "The authentication path must continue operating without internet access, hosted identity or licensing phone-home.",
      ],
      [
        "Approved authenticators",
        "Credential policy must distinguish issued, device-bound hardware from unmanaged or synchronised passkeys.",
      ],
      [
        "Controlled operations",
        "Installation media, updates, keys, recovery and audit export need reviewable offline procedures.",
      ],
    ],
    capabilities: [
      ["Self-contained core", "RustyAuth and its private data store can run within one controlled network."],
      [
        "Phishing resistance",
        "WebAuthn binds authenticator output to the configured relying-party identity.",
      ],
      [
        "Fail-closed state",
        "Invalid configuration, missing trust state and incomplete recovery prevent normal operation.",
      ],
    ],
    boundary: [
      ["01", "Issued security key", "Holds a device-bound credential"],
      ["02", "Local application", "Runs on the trusted internal origin"],
      ["03", "RustyAuth enclave", "Verifies locally and issues tokens"],
      ["04", "Private persistence", "Keeps identity and signing state inside"],
    ],
    doesNotReplace: [
      "Personnel vetting or identity proofing",
      "Endpoint and network security",
      "Application authorisation policy",
      "Formal accreditation or approved cryptographic modules",
    ],
    productionNeeds: [
      "Offline signed release bundles and SBOMs",
      "Authenticator attestation and allowlisting",
      "HSM or approved cryptographic integration",
      "Independent assessment and assured support",
    ],
  },
];

export const solutionBySlug = (slug: string) => solutions.find((solution) => solution.slug === slug);
