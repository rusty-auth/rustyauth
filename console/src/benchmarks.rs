use serde::Deserialize;

const CATALOGUE_JSON: &str = include_str!("../../benchmarks/catalog.json");

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkCatalogue {
    pub schema_version: u32,
    pub updated_at: String,
    pub publication_policy: PublicationPolicy,
    pub programs: Vec<BenchmarkProgram>,
    pub reports: Vec<BenchmarkReport>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct PublicationPolicy {
    pub summary: String,
    pub isolation: String,
    pub promotion: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkProgram {
    pub id: String,
    pub title: String,
    pub state: String,
    pub summary: String,
    pub schedule: Vec<String>,
    pub resource_tiers: Vec<ResourceTier>,
    pub user_profiles: Vec<UserProfile>,
    pub gates: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTier {
    pub name: String,
    pub api: String,
    pub sable_db: String,
    pub dataset_accounts: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    pub name: String,
    pub requests_per_minute: u64,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkReport {
    pub id: String,
    pub program_id: String,
    pub title: String,
    pub status: String,
    pub qualification: String,
    pub observed_at: String,
    pub release: String,
    pub commit: String,
    pub environment: String,
    pub methodology_version: String,
    pub summary: String,
    pub dataset: Vec<BenchmarkDatum>,
    pub results: Vec<BenchmarkResult>,
    pub evidence: Vec<EvidenceLink>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct BenchmarkDatum {
    pub key: String,
    pub label: String,
    pub value: f64,
    pub unit: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct BenchmarkResult {
    pub key: String,
    pub label: String,
    pub value: f64,
    pub unit: String,
    pub threshold: String,
    pub outcome: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct EvidenceLink {
    pub label: String,
    pub url: String,
}

pub fn catalogue() -> Result<BenchmarkCatalogue, serde_json::Error> {
    serde_json::from_str(CATALOGUE_JSON)
}

#[cfg(test)]
mod tests {
    use super::catalogue;

    #[test]
    fn embedded_catalogue_contains_the_reviewed_realm_baseline() {
        let catalogue = catalogue().expect("benchmark catalogue should parse");
        assert_eq!(catalogue.schema_version, 1);
        let realm = catalogue
            .programs
            .iter()
            .find(|program| program.id == "single-realm-capacity")
            .expect("realm capacity programme");
        assert_eq!(realm.state, "active");
        let report = catalogue
            .reports
            .iter()
            .find(|report| report.program_id == realm.id && report.status == "passed")
            .expect("passed single-realm report");
        assert!(
            report.results.iter().any(
                |result| result.key == "sustainable_authenticated_rps" && result.value == 800.0
            )
        );
        assert!(
            report
                .results
                .iter()
                .any(|result| result.key == "supported_typical_active_users"
                    && result.value == 5600.0)
        );
    }
}
