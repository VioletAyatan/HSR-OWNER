//! Tokenizes method signatures only to find top-level Proto parameter candidates.
//! This is a selection hint, not a substitute for reflection or ABI validation.
use std::collections::HashSet;

fn valid_component(component: &str) -> bool {
    let mut delimiters: Vec<(char, usize)> = Vec::new();
    for (index, ch) in component.char_indices() {
        match ch {
            '<' | '[' => delimiters.push((ch, index + ch.len_utf8())),
            '>' => {
                let Some((open, slot_start)) = delimiters.pop() else {
                    return false;
                };
                if open != '<' || component[slot_start..index].trim().is_empty() {
                    return false;
                }
            }
            ']' => {
                if delimiters.pop().is_none_or(|(open, _)| open != '[') {
                    return false;
                }
            }
            ',' => match delimiters.last_mut() {
                Some(('<', slot_start)) => {
                    if component[*slot_start..index].trim().is_empty() {
                        return false;
                    }
                    *slot_start = index + ch.len_utf8();
                }
                Some(('[', _)) => {} // Array-rank commas are syntax, not empty parameters.
                _ => return false,
            },
            '(' | ')' => return false,
            _ => {}
        }
    }
    delimiters.is_empty()
}

fn parameters(signature: &str) -> Option<Vec<&str>> {
    let (owner, method) = signature.rsplit_once("::")?;
    if owner.is_empty() || !valid_component(owner) {
        return None;
    }
    let (name, args_with_close) = method.split_once('(')?;
    if name.is_empty() || !valid_component(name) || !args_with_close.ends_with(')') {
        return None;
    }
    let args = &args_with_close[..args_with_close.len() - 1];
    if args.contains(['(', ')']) {
        return None;
    }
    if args.is_empty() {
        return Some(Vec::new());
    }

    let mut params = Vec::new();
    let mut delimiters = Vec::new();
    let mut start = 0;
    for (index, ch) in args.char_indices() {
        match ch {
            '<' | '[' => delimiters.push(ch),
            '>' => {
                if delimiters.pop() != Some('<') {
                    return None;
                }
            }
            ']' => {
                if delimiters.pop() != Some('[') {
                    return None;
                }
            }
            ',' if delimiters.is_empty() => {
                let parameter = &args[start..index];
                if parameter.is_empty() || parameter.trim() != parameter {
                    return None;
                }
                if !valid_component(parameter) {
                    return None;
                }
                params.push(parameter);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    if !delimiters.is_empty() {
        return None;
    }
    let last = &args[start..];
    if last.is_empty() || last.trim() != last {
        return None;
    }
    if !valid_component(last) {
        return None;
    }
    params.push(last);
    Some(params)
}

/// Return true when a normal method signature has a top-level argument whose
/// complete type name matches a current Proto message (with optional `Proto.`).
/// This does not bind the method, count Proto arguments, or establish copy ABI.
pub(super) fn has_proto_parameter(signature: &str, message_names: &HashSet<String>) -> bool {
    let Some((_, method)) = signature.rsplit_once("::") else {
        return false;
    };
    let Some((name, _)) = method.split_once('(') else {
        return false;
    };
    if matches!(name, ".ctor" | ".cctor") {
        return false;
    }
    parameters(signature).is_some_and(|params| {
        params.into_iter().any(|parameter| {
            message_names.contains(parameter)
                || parameter
                    .strip_prefix("Proto.")
                    .is_some_and(|name| message_names.contains(name))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::has_proto_parameter;
    use std::collections::HashSet;

    fn names() -> HashSet<String> {
        HashSet::from(["ABCDEFGHIJK".to_owned(), "LMNOPQRSTUV".to_owned()])
    }

    #[test]
    fn matches_only_exact_top_level_proto_types_in_any_parameter_position() {
        let names = names();
        for signature in [
            "Owner::M(ABCDEFGHIJK,System.Int32,System.String)",
            "Owner::M(System.Int32,Proto.ABCDEFGHIJK,System.String)",
            "Owner::M(System.Int32,System.String,LMNOPQRSTUV)",
        ] {
            assert!(has_proto_parameter(signature, &names), "{signature}");
        }
        assert!(has_proto_parameter(
            "Owner::M(ABCDEFGHIJK,Proto.LMNOPQRSTUV)",
            &names
        ));
    }

    #[test]
    fn balances_generic_commas_and_array_rank_commas() {
        let names = names();
        assert!(has_proto_parameter(
            "Owner::M(Dictionary<System.String,List<System.Int32>>,Proto.ABCDEFGHIJK)",
            &names
        ));
        assert!(has_proto_parameter(
            "Owner::M(Dictionary<System.String,List<System.Int32>>[,,],System.Int32,LMNOPQRSTUV)",
            &names
        ));
        assert!(!has_proto_parameter(
            "Owner::M(Dictionary<System.String,Proto.ABCDEFGHIJK>)",
            &names
        ));
        assert!(!has_proto_parameter("Owner::M(ABCDEFGHIJK[])", &names));
    }

    #[test]
    fn rejects_bad_signatures_empty_slots_and_constructors() {
        let names = names();
        for signature in [
            "M(ABCDEFGHIJK)",
            "Owner::M(ABCDEFGHIJK",
            "Owner::M(ABCDEFGHIJK))",
            "Owner::M(,ABCDEFGHIJK)",
            "Owner::M(ABCDEFGHIJK,)",
            "Owner::M(ABCDEFGHIJK,,System.Int32)",
            "Owner::M(Dictionary<System.String,ABCDEFGHIJK)",
            "Owner::M(Dictionary<System.String],ABCDEFGHIJK)",
            "Owner::M(Dictionary<System.String,,ABCDEFGHIJK>)",
            "Owner::M(ABCDEFGHIJK,Dictionary<>)",
            "Owner<>::M(ABCDEFGHIJK)",
            "Owner::M(Wrapper<(ABCDEFGHIJK)>)",
            "Owner::.ctor(ABCDEFGHIJK)",
            "Owner::.cctor(Proto.ABCDEFGHIJK)",
            "Owner::M(UnrelatedType)",
        ] {
            assert!(!has_proto_parameter(signature, &names), "{signature}");
        }
    }
}
