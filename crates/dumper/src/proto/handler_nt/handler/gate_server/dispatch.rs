use std::{borrow::Cow, sync::LazyLock, time::Duration};

use il2cpp::{get_cached_class, vm::string::Il2CppString};
use reflection::runtime_type::RuntimeType;

use super::{decoder, region};

#[path = "dispatch_retry.rs"]
mod retry;

static HTTP_AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .timeout_connect(Some(Duration::from_secs(5)))
        .build();
    ureq::Agent::new_with_config(config)
});

pub static DISPATCH_SEED: LazyLock<Cow<'static, str>> = LazyLock::new(|| {
    let gv = RuntimeType::from_class(get_cached_class("RPG.Client.GlobalVars").unwrap()).unwrap();
    let seed = gv
        .get_field("s_VersionData".into(), 62)
        .unwrap()
        .get_value(il2cpp::vm::object::Il2CppObject::NULL)
        .unwrap();
    RuntimeType::from_object(seed)
        .unwrap()
        .get_method("GetDispatchSeed".into(), 62)
        .unwrap()
        .get_il2cpp_method()
        .invoke::<Il2CppString>(seed, &[])
        .unwrap()
        .as_str()
});

pub fn get_dispatch_url() -> Option<String> {
    let cfg = (|| {
        let rt = get_cached_class("RPG.Client.ClientStartupConfig")?;
        let rt = RuntimeType::from_class(rt).ok()?;
        rt.get_property("Data".into(), 62)
            .ok()?
            .get_get_method(true)
            .ok()?
            .get_il2cpp_method()
            .invoke(il2cpp::vm::object::Il2CppObject::NULL, &[])
            .ok()
    })()?;

    (|| {
        let rt = RuntimeType::from_object(cfg).ok()?;
        let f = rt.get_field("GlobalDispatchUrlList".into(), 62).ok()?;
        let v = f.get_value(cfg).ok()?;
        let arr = il2cpp::vm::array::Il2CppArray(v.0);
        arr.to_vec::<Il2CppString>()
            .into_iter()
            .next()
            .map(|s| s.as_str().to_string())
    })()
}

fn http_get(url: &str) -> Result<Vec<u8>, retry::Failure> {
    // Keep ureq's existing 10 MiB response-body bound. The global timeout also
    // covers redirects and reading the body; no individual attempt can wait
    // indefinitely on an unavailable dispatch server.
    HTTP_AGENT
        .get(url)
        .call()
        .map_err(|error| retry::Failure::http("http-request", &error))?
        .into_body()
        .read_to_vec()
        .map_err(|error| retry::Failure::http("http-body", &error))
}

fn base64_decode(data: &str) -> Result<Vec<u8>, retry::Failure> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data.trim())
        .map_err(|error| retry::Failure::base64(&error))
}

fn decoded_response(url: &str) -> Result<decoder::DecodingResult, retry::Failure> {
    let response = http_get(url)?;
    let blob = base64_decode(&String::from_utf8_lossy(&response))?;
    decoder::Decoder::new(blob)
        .decode()
        .map_err(|error| retry::Failure::wire(&error))
}

fn gateway_from_wire(result: decoder::DecodingResult) -> Result<String, retry::Failure> {
    let dispatch = region::Dispatch::from_wire(result)
        .ok_or_else(|| retry::Failure::semantic("dispatch-schema", None))?;
    if dispatch.retcode != 0 {
        // Server stop text is response content, not a safe diagnostic. Preserve
        // the numeric failure and do not turn an explicit refusal into a retry.
        return Err(retry::Failure::semantic(
            "dispatch-retcode",
            Some(dispatch.retcode),
        ));
    }
    let region = dispatch
        .region_list
        .first()
        .ok_or_else(|| retry::Failure::semantic("dispatch-regions-empty", None))?;
    if !region.dispatch_url.is_empty() {
        Ok(region.dispatch_url.clone())
    } else if !region.sub_dispatch_url.is_empty() {
        log::debug!("[Gateway] dispatch_url empty, using sub_dispatch_url");
        Ok(region.sub_dispatch_url.clone())
    } else {
        Err(retry::Failure::semantic("dispatch-gateway-url-empty", None))
    }
}

pub fn fetch_gateway_url(dispatch_url: &str, version: &str) -> Option<String> {
    let path = format!(
        "{dispatch_url}?version={version}&language_type=3&platform_type=3&channel_id=1&sub_channel_id=1&is_new_format=1"
    );
    retry::run("dispatch", || gateway_from_wire(decoded_response(&path)?))
}

pub fn fetch_gateway_response(
    gateway_url: &str,
    version: &str,
    seed: &str,
) -> Option<decoder::DecodingResult> {
    let path = format!(
        "{gateway_url}?version={version}&platform_type=1&language_type=3&dispatch_seed={seed}&channel_id=1&sub_channel_id=1&is_need_url=1"
    );
    retry::run("gateway", || decoded_response(&path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use decoder::{Decoded, DecodedValue, DecodingResult, WireType};

    fn wire(fields: Vec<Decoded>) -> DecodingResult {
        DecodingResult {
            fields,
            unprocessed: Vec::new(),
        }
    }

    #[test]
    fn dispatch_refusal_and_missing_regions_remain_failure() {
        let error = gateway_from_wire(wire(vec![Decoded {
            field: 1,
            wire_type: WireType::VarInt,
            is_object: false,
            value: DecodedValue::BigInt(7),
        }]))
        .unwrap_err();
        assert!(!error.retryable);
        assert_eq!(error.reason, "dispatch-retcode");
        assert_eq!(error.code, Some(7));
        let empty = gateway_from_wire(wire(Vec::new())).unwrap_err();
        assert!(!empty.retryable);
        assert_eq!(empty.reason, "dispatch-regions-empty");
    }

    #[test]
    fn dispatch_requires_an_actual_region_gateway_url() {
        for (field, url) in [(3, "https://dispatch.invalid"), (7, "https://sub.invalid")] {
            let region = Decoded {
                field: 4,
                wire_type: WireType::Len,
                is_object: true,
                value: DecodedValue::Nested(wire(vec![Decoded {
                    field,
                    wire_type: WireType::Len,
                    is_object: false,
                    value: DecodedValue::Buffer(url.as_bytes().to_vec()),
                }])),
            };
            assert_eq!(gateway_from_wire(wire(vec![region])).unwrap(), url);
        }
        let empty_region = Decoded {
            field: 4,
            wire_type: WireType::Len,
            is_object: true,
            value: DecodedValue::Nested(wire(Vec::new())),
        };
        let error = gateway_from_wire(wire(vec![empty_region])).unwrap_err();
        assert!(!error.retryable);
        assert_eq!(error.reason, "dispatch-gateway-url-empty");
    }
}
