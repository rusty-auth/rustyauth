//! Browser-facing binary Connect client and passkey ceremony adapter.

use buffa::Message;

use crate::proto::rustyauth::fleet::v1::*;

#[cfg(target_arch = "wasm32")]
const FLEET_PREFIX: &str = "/rustyauth.fleet.v1.FleetService/";
#[cfg(target_arch = "wasm32")]
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientError(pub String);

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub async fn overview(organization_id: Option<&str>) -> Result<FleetOverview, ClientError> {
    rpc(
        "GetFleetOverview",
        &GetFleetOverviewRequest {
            organization_id: organization_id.unwrap_or_default().to_owned(),
            ..Default::default()
        },
    )
    .await
}

pub async fn organizations() -> Result<Vec<Organization>, ClientError> {
    let response: ListOrganizationsResponse = rpc(
        "ListOrganizations",
        &ListOrganizationsRequest {
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.organizations)
}

pub async fn create_organization(slug: &str, name: &str) -> Result<Organization, ClientError> {
    rpc(
        "CreateOrganization",
        &CreateOrganizationRequest {
            slug: slug.to_owned(),
            name: name.to_owned(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: "Created from the Fleet dashboard".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn projects(organization_id: &str) -> Result<Vec<Project>, ClientError> {
    let response: ListProjectsResponse = rpc(
        "ListProjects",
        &ListProjectsRequest {
            organization_id: organization_id.to_owned(),
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.projects)
}

pub async fn create_project(
    organization_id: &str,
    slug: &str,
    name: &str,
) -> Result<Project, ClientError> {
    rpc(
        "CreateProject",
        &CreateProjectRequest {
            organization_id: organization_id.to_owned(),
            slug: slug.to_owned(),
            name: name.to_owned(),
            description: String::new(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: "Created from the Fleet dashboard".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn environments(
    organization_id: &str,
    project_id: &str,
) -> Result<Vec<Environment>, ClientError> {
    let response: ListEnvironmentsResponse = rpc(
        "ListEnvironments",
        &ListEnvironmentsRequest {
            organization_id: organization_id.to_owned(),
            project_id: project_id.to_owned(),
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.environments)
}

pub async fn create_environment(
    organization_id: &str,
    project_id: &str,
    slug: &str,
    name: &str,
    kind: EnvironmentKind,
) -> Result<Environment, ClientError> {
    rpc(
        "CreateEnvironment",
        &CreateEnvironmentRequest {
            organization_id: organization_id.to_owned(),
            project_id: project_id.to_owned(),
            slug: slug.to_owned(),
            name: name.to_owned(),
            kind: kind.into(),
            provider: "Railway".into(),
            region: "Auto".into(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: "Created from the Fleet dashboard".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn connections(
    organization_id: &str,
    project_id: Option<&str>,
    environment_id: Option<&str>,
) -> Result<Vec<RealmConnection>, ClientError> {
    let response: ListConnectionsResponse = rpc(
        "ListConnections",
        &ListConnectionsRequest {
            organization_id: organization_id.to_owned(),
            project_id: project_id.unwrap_or_default().to_owned(),
            environment_id: environment_id.unwrap_or_default().to_owned(),
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.connections)
}

pub async fn audit_events(organization_id: Option<&str>) -> Result<Vec<AuditEvent>, ClientError> {
    let response: ListAuditEventsResponse = rpc(
        "ListAuditEvents",
        &ListAuditEventsRequest {
            organization_id: organization_id.unwrap_or_default().to_owned(),
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.events)
}

pub async fn begin_connection(
    organization_id: &str,
    project_id: &str,
    environment_id: &str,
    endpoint: &str,
) -> Result<ConnectionAttempt, ClientError> {
    rpc(
        "BeginConnection",
        &BeginConnectionRequest {
            organization_id: organization_id.to_owned(),
            project_id: project_id.to_owned(),
            environment_id: environment_id.to_owned(),
            mode: ConnectionMode::PublicEndpoint.into(),
            management_endpoint: endpoint.to_owned(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: "Pair realm from the Fleet dashboard".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn complete_connection(
    attempt_id: &str,
    pairing_code: &str,
) -> Result<RealmConnection, ClientError> {
    rpc(
        "CompleteConnection",
        &CompleteConnectionRequest {
            attempt_id: attempt_id.to_owned(),
            pairing_code: pairing_code.to_owned(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: "Complete realm pairing from the Fleet dashboard".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

#[cfg(target_arch = "wasm32")]
pub async fn sign_out() -> Result<(), ClientError> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestCredentials, RequestInit, RequestMode, Response};

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_mode(RequestMode::SameOrigin);
    init.set_credentials(RequestCredentials::SameOrigin);
    let request =
        web_sys::Request::new_with_str_and_init("/v1/sign-out", &init).map_err(js_error)?;
    let response = JsFuture::from(
        web_sys::window()
            .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
            .fetch_with_request(&request),
    )
    .await
    .map_err(js_error)?
    .dyn_into::<Response>()
    .map_err(|_| ClientError("RustyAuth returned an invalid response.".into()))?;
    if response.ok() {
        Ok(())
    } else {
        Err(ClientError("RustyAuth could not close the session.".into()))
    }
}

#[cfg(target_arch = "wasm32")]
pub async fn register_operator_passkey(
    email: &str,
    display_name: &str,
    bootstrap_token: &str,
) -> Result<(), ClientError> {
    use js_sys::{Function, Promise, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let options = fetch_json_with_bootstrap(
        "/v1/passkeys/registration/options",
        &serde_json::json!({
            "email": email,
            "displayName": display_name,
        }),
        Some(bootstrap_token),
    )
    .await?;
    let ceremony_id = options
        .get("ceremonyId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ClientError("RustyAuth returned an invalid ceremony.".into()))?;
    let options_json = public_key_options(&options)?;
    let public_key = serde_wasm_bindgen::to_value(options_json)
        .map_err(|error| ClientError(error.to_string()))?;
    let constructor = Reflect::get(&js_sys::global(), &JsValue::from_str("PublicKeyCredential"))
        .map_err(js_error)?;
    let parser = Reflect::get(
        &constructor,
        &JsValue::from_str("parseCreationOptionsFromJSON"),
    )
    .map_err(js_error)?
    .dyn_into::<Function>()
    .map_err(|_| ClientError("This browser cannot parse passkey options.".into()))?;
    let parsed = parser.call1(&constructor, &public_key).map_err(js_error)?;
    let request = js_sys::Object::new();
    Reflect::set(&request, &JsValue::from_str("publicKey"), &parsed).map_err(js_error)?;
    let credentials = web_sys::window()
        .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
        .navigator()
        .credentials();
    let create = Reflect::get(credentials.as_ref(), &JsValue::from_str("create"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot create passkeys.".into()))?;
    let promise = create
        .call1(credentials.as_ref(), request.as_ref())
        .map_err(js_error)?
        .dyn_into::<Promise>()
        .map_err(|_| ClientError("This browser returned an invalid passkey request.".into()))?;
    let credential = JsFuture::from(promise).await.map_err(js_error)?;
    let to_json = Reflect::get(&credential, &JsValue::from_str("toJSON"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot serialize a passkey response.".into()))?;
    let response = to_json.call0(&credential).map_err(js_error)?;
    let response: serde_json::Value =
        serde_wasm_bindgen::from_value(response).map_err(|error| ClientError(error.to_string()))?;
    fetch_json_with_bootstrap(
        "/v1/passkeys/registration/verify",
        &serde_json::json!({ "ceremonyId": ceremony_id, "response": response }),
        Some(bootstrap_token),
    )
    .await?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn register_operator_passkey(
    _email: &str,
    _display_name: &str,
    _bootstrap_token: &str,
) -> Result<(), ClientError> {
    Err(ClientError(
        "Native passkey enrolment requires the platform credential adapter.".into(),
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sign_out() -> Result<(), ClientError> {
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub async fn authenticate_passkey(email: &str) -> Result<(), ClientError> {
    use js_sys::{Function, Promise, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let options = fetch_json(
        "/v1/passkeys/authentication/options",
        &serde_json::json!({ "email": email }),
    )
    .await?;
    let ceremony_id = options
        .get("ceremonyId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ClientError("RustyAuth returned an invalid ceremony.".into()))?;
    let public_key = serde_wasm_bindgen::to_value(public_key_options(&options)?)
        .map_err(|error| ClientError(error.to_string()))?;
    let constructor = Reflect::get(&js_sys::global(), &JsValue::from_str("PublicKeyCredential"))
        .map_err(js_error)?;
    let parser = Reflect::get(
        &constructor,
        &JsValue::from_str("parseRequestOptionsFromJSON"),
    )
    .map_err(js_error)?
    .dyn_into::<Function>()
    .map_err(|_| ClientError("This browser cannot parse passkey options.".into()))?;
    let parsed = parser.call1(&constructor, &public_key).map_err(js_error)?;
    let request = js_sys::Object::new();
    Reflect::set(&request, &JsValue::from_str("publicKey"), &parsed).map_err(js_error)?;
    let credentials = web_sys::window()
        .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
        .navigator()
        .credentials();
    let get = Reflect::get(credentials.as_ref(), &JsValue::from_str("get"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot request passkeys.".into()))?;
    let promise = get
        .call1(credentials.as_ref(), request.as_ref())
        .map_err(js_error)?
        .dyn_into::<Promise>()
        .map_err(|_| ClientError("This browser returned an invalid passkey request.".into()))?;
    let credential = JsFuture::from(promise).await.map_err(js_error)?;
    let to_json = Reflect::get(&credential, &JsValue::from_str("toJSON"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot serialize a passkey response.".into()))?;
    let response = to_json.call0(&credential).map_err(js_error)?;
    let response: serde_json::Value =
        serde_wasm_bindgen::from_value(response).map_err(|error| ClientError(error.to_string()))?;
    fetch_json(
        "/v1/passkeys/authentication/verify",
        &serde_json::json!({ "ceremonyId": ceremony_id, "response": response }),
    )
    .await?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn authenticate_passkey(_email: &str) -> Result<(), ClientError> {
    Err(ClientError(
        "Native passkey support requires the platform credential adapter.".into(),
    ))
}

#[cfg(target_arch = "wasm32")]
async fn rpc<Request, Response>(method: &str, request: &Request) -> Result<Response, ClientError>
where
    Request: Message,
    Response: Message,
{
    use js_sys::Uint8Array;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestCredentials, RequestInit, RequestMode, Response as WebResponse};

    let bytes = request.encode_to_vec();
    let body = Uint8Array::from(bytes.as_slice());
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_mode(RequestMode::SameOrigin);
    init.set_credentials(RequestCredentials::SameOrigin);
    init.set_body(&body);
    let web_request =
        web_sys::Request::new_with_str_and_init(&format!("{FLEET_PREFIX}{method}"), &init)
            .map_err(js_error)?;
    web_request
        .headers()
        .set("Content-Type", "application/proto")
        .map_err(js_error)?;
    web_request
        .headers()
        .set("Connect-Protocol-Version", "1")
        .map_err(js_error)?;
    let response = JsFuture::from(
        web_sys::window()
            .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
            .fetch_with_request(&web_request),
    )
    .await
    .map_err(js_error)?
    .dyn_into::<WebResponse>()
    .map_err(|_| ClientError("Fleet returned an invalid response.".into()))?;
    if !response.ok() {
        return Err(ClientError(connect_error_message(&response).await));
    }
    let buffer = JsFuture::from(response.array_buffer().map_err(js_error)?)
        .await
        .map_err(js_error)?;
    let bytes = Uint8Array::new(&buffer).to_vec();
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ClientError(
            "Fleet response exceeded the safety limit.".into(),
        ));
    }
    Response::decode_from_slice(&bytes)
        .map_err(|_| ClientError("Fleet returned invalid Protobuf.".into()))
}

#[cfg(not(target_arch = "wasm32"))]
async fn rpc<Request, Response>(_method: &str, _request: &Request) -> Result<Response, ClientError>
where
    Request: Message,
    Response: Message,
{
    Err(ClientError(
        "Set up the native Fleet transport adapter for this target.".into(),
    ))
}

#[cfg(target_arch = "wasm32")]
async fn fetch_json(
    path: &str,
    value: &serde_json::Value,
) -> Result<serde_json::Value, ClientError> {
    fetch_json_with_bootstrap(path, value, None).await
}

#[cfg(target_arch = "wasm32")]
async fn fetch_json_with_bootstrap(
    path: &str,
    value: &serde_json::Value,
    bootstrap_token: Option<&str>,
) -> Result<serde_json::Value, ClientError> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestCredentials, RequestInit, RequestMode, Response};

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_mode(RequestMode::SameOrigin);
    init.set_credentials(RequestCredentials::SameOrigin);
    init.set_body(&wasm_bindgen::JsValue::from_str(&value.to_string()));
    let request = web_sys::Request::new_with_str_and_init(path, &init).map_err(js_error)?;
    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(js_error)?;
    if let Some(token) = bootstrap_token {
        request
            .headers()
            .set("X-Bootstrap-Token", token)
            .map_err(js_error)?;
    }
    let response = JsFuture::from(
        web_sys::window()
            .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
            .fetch_with_request(&request),
    )
    .await
    .map_err(js_error)?
    .dyn_into::<Response>()
    .map_err(|_| ClientError("RustyAuth returned an invalid response.".into()))?;
    let body = JsFuture::from(response.text().map_err(js_error)?)
        .await
        .map_err(js_error)?
        .as_string()
        .unwrap_or_default();
    if !response.ok() {
        return Err(ClientError(
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| value.get("error")?.as_str().map(str::to_owned))
                .unwrap_or_else(|| "RustyAuth rejected the request.".into()),
        ));
    }
    serde_json::from_str(&body).map_err(|_| ClientError("RustyAuth returned invalid JSON.".into()))
}

#[cfg(target_arch = "wasm32")]
fn public_key_options(value: &serde_json::Value) -> Result<&serde_json::Value, ClientError> {
    let options = value
        .get("options")
        .ok_or_else(|| ClientError("RustyAuth returned invalid passkey options.".into()))?;
    Ok(options.get("publicKey").unwrap_or(options))
}

#[cfg(target_arch = "wasm32")]
async fn connect_error_message(response: &web_sys::Response) -> String {
    use wasm_bindgen_futures::JsFuture;
    let body = match response.text() {
        Ok(promise) => JsFuture::from(promise)
            .await
            .ok()
            .and_then(|value| value.as_string())
            .unwrap_or_default(),
        Err(_) => String::new(),
    };
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("message")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("Fleet request failed with HTTP {}.", response.status()))
}

#[cfg(target_arch = "wasm32")]
fn js_error(value: wasm_bindgen::JsValue) -> ClientError {
    ClientError(
        value
            .as_string()
            .unwrap_or_else(|| "Browser operation failed.".into()),
    )
}

fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
