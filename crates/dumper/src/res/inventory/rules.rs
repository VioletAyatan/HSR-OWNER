//! Root-type rules for DesignData entries that no earlier export route reached.
//!
//! The index stores no type information, so each logical path is mapped to an
//! ordered list of `GameCoreConfigLoader` loaders (whose deserializer is then
//! run on the entry bytes and accepted only on exact consumption):
//!
//! 1. `O` path-prefix overrides (families mixing types, e.g. HeartDial),
//! 2. `F` family rules (directory with digit runs as `#`, filename letter
//!    prefix and secondary extensions), generated offline from exact decodes,
//!    the runtime loader log and client cross-references,
//! 3. bake layouts (`.layout.` is inserted by `BinaryBakeLayoutPath`),
//! 4. `D` directory defaults (longest prefix) for families added later.
use std::collections::{BTreeSet, HashMap};

static RULES_TSV: &str = include_str!("../../../resources/designdata/rules.tsv");
const LAYOUT_LOADER: &str = "LoadConfigBakeLayoutInfoList";

/// How much evidence backs a rule's loader choice. Failed decodes disable
/// weakly backed rules sooner, because a wrong root type can read garbage
/// lengths and allocate gigabytes before the deserializer gives up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// Name similarity between the path and a loaded type only.
    Guessed,
    /// Directory naming convention.
    Inferred,
    /// Offline exact decodes of entries in the family.
    Sniffed,
    /// Runtime loader log, client cross-reference or client path transform.
    Proven,
}

impl Strength {
    /// Strongest evidence named in a rules.tsv evidence column.
    pub fn from_evidence(kind: &str, evidence: &str) -> Self {
        if kind == "O" {
            return Self::Proven;
        }
        evidence
            .split(';')
            .map(|part| {
                let part = part.trim();
                if part.starts_with("runtime truth") || part.starts_with("client ") {
                    Self::Proven
                } else if part.starts_with("sniff") {
                    Self::Sniffed
                } else if part.starts_with("name:") {
                    Self::Guessed
                } else {
                    Self::Inferred
                }
            })
            .max()
            .unwrap_or(Self::Inferred)
    }
}

struct Rule {
    loaders: Vec<String>,
    strength: Strength,
}

/// The rule chosen for one entry.
pub struct Selection<'a> {
    pub loaders: Vec<&'a str>,
    /// Which tier matched: override, family, layout or default.
    pub tier: &'static str,
    /// The matched rule's key (path prefix or family key).
    pub key: String,
    pub strength: Strength,
}

pub struct Rules {
    overrides: Vec<(String, Rule)>,
    families: HashMap<String, Rule>,
    defaults: Vec<(String, Rule)>,
}

/// `BakedConfig/Config/A/B.bytes` -> `Config/A/B.json` (inverse of
/// `GameCoreConfigLoader.JsonToBinaryPath`).
pub fn json_path(logical: &str) -> Option<String> {
    let rest = logical.strip_prefix("BakedConfig/")?;
    let stem = rest.strip_suffix(".bytes")?;
    (!stem.is_empty() && !stem.ends_with('/')).then(|| format!("{stem}.json"))
}

/// Family key; must stay identical to `family()` in the generator.
pub fn family_key(logical: &str) -> String {
    let path = logical.strip_prefix("BakedConfig/").unwrap_or(logical);
    let (dir, file) = path.rsplit_once('/').unwrap_or(("", path));
    let mut key = String::with_capacity(path.len());
    let mut in_digits = false;
    for c in dir.chars() {
        if c.is_ascii_digit() {
            if !in_digits {
                key.push('#');
            }
            in_digits = true;
        } else {
            key.push(c);
            in_digits = false;
        }
    }
    key.push('/');
    let stem = file.strip_suffix(".bytes").unwrap_or(file);
    let prefix: String = stem
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .take(24)
        .collect();
    key.push_str(&prefix);
    key.push('*');
    // Every `.<letters/underscores>` run, in order (Python `\.[A-Za-z_]+`).
    let bytes = stem.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphabetic() || bytes[end] == b'_') {
                end += 1;
            }
            if end > start {
                key.push_str(&stem[i..end]);
                i = end;
                continue;
            }
        }
        i += 1;
    }
    key
}

impl Rules {
    pub fn embedded() -> Self {
        Self::parse(RULES_TSV)
    }

    pub fn parse(text: &str) -> Self {
        let mut rules = Self {
            overrides: Vec::new(),
            families: HashMap::new(),
            defaults: Vec::new(),
        };
        for line in text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let mut columns = line.split('\t');
            let (Some(kind), Some(key), Some(loaders)) =
                (columns.next(), columns.next(), columns.next())
            else {
                continue;
            };
            let rule = Rule {
                loaders: loaders
                    .split('|')
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect(),
                strength: Strength::from_evidence(kind, columns.next().unwrap_or("")),
            };
            match kind {
                "O" => rules.overrides.push((key.to_string(), rule)),
                "F" => {
                    rules.families.insert(key.to_string(), rule);
                }
                "D" => rules.defaults.push((key.to_string(), rule)),
                _ => {}
            }
        }
        // Longest prefix first.
        rules.overrides.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        rules.defaults.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        rules
    }

    pub fn family_count(&self) -> usize {
        self.families.len()
    }

    /// Every loader any rule can select.
    pub fn loader_names(&self) -> BTreeSet<String> {
        self.overrides
            .iter()
            .chain(self.defaults.iter())
            .map(|(_, rule)| rule)
            .chain(self.families.values())
            .flat_map(|rule| rule.loaders.iter())
            .cloned()
            .chain(std::iter::once(LAYOUT_LOADER.to_string()))
            .collect()
    }

    /// Ordered loader candidates and the rule that selected them.
    pub fn candidates(&self, logical: &str) -> Option<Selection<'_>> {
        fn select<'a>(tier: &'static str, key: &str, rule: &'a Rule) -> Selection<'a> {
            Selection {
                loaders: rule.loaders.iter().map(String::as_str).collect(),
                tier,
                key: key.to_string(),
                strength: rule.strength,
            }
        }
        let json = json_path(logical)?;
        if let Some((prefix, rule)) = self
            .overrides
            .iter()
            .find(|(p, _)| json.starts_with(p.as_str()))
        {
            return Some(select("override", prefix, rule));
        }
        let family = family_key(logical);
        if let Some(rule) = self.families.get(&family) {
            return Some(select("family", &family, rule));
        }
        let file = json.rsplit('/').next().unwrap_or(&json);
        if file.contains(".layout.") {
            return Some(Selection {
                loaders: vec![LAYOUT_LOADER],
                tier: "layout",
                key: family,
                strength: Strength::Proven,
            });
        }
        self.defaults
            .iter()
            .find(|(p, _)| json.starts_with(p.as_str()))
            .map(|(prefix, rule)| select("default", prefix, rule))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_keys_match_generator() {
        let cases = [
            (
                "BakedConfig/Config/Level/Mission/1000101/Act/Act100010101.bytes",
                "Config/Level/Mission/#/Act/Act*",
            ),
            (
                "BakedConfig/Config/Level/Mission/1000101/MissionInfo_1000101.partial.layout.bytes",
                "Config/Level/Mission/#/MissionInfo*.partial.layout",
            ),
            (
                "BakedConfig/Config/Level/NPCDialogue/P20101/F20101001_G12/DialogueMain_201.bytes",
                "Config/Level/NPCDialogue/P#/F#_G#/DialogueMain*",
            ),
            (
                "BakedConfig/Config/ConfigAbility/BattleEvent/GridFight/3.5/AvatarAbility/X.layout.bytes",
                "Config/ConfigAbility/BattleEvent/GridFight/#.#/AvatarAbility/X*.layout",
            ),
            ("BakedConfig/ConfigManifest.json", "/ConfigManifest*.json"),
        ];
        for (path, key) in cases {
            assert_eq!(family_key(path), key, "{path}");
        }
    }

    #[test]
    fn json_path_inverts_binary_path() {
        assert_eq!(
            json_path("BakedConfig/Config/A/B.layout.bytes").as_deref(),
            Some("Config/A/B.layout.json")
        );
        assert_eq!(json_path("BakedConfig/ConfigManifest.json"), None);
        assert_eq!(json_path("Config/A.bytes"), None);
    }

    #[test]
    fn rule_tiers_apply_in_order() {
        let rules = Rules::parse(
            "# header\n\
             O\tConfig/LevelOutput/HeartDial/HeartDial_Floor_\tLoadFloor\tx\n\
             F\tConfig/Level/MunicipalChatConfig/F#/MunicipalChatConfig*\tLoadChat\tx\n\
             F\tConfig/LevelOutput/HeartDial/HeartDial*\tLoadWrong\tx\n\
             D\tConfig/Level/\tLoadGraph\tx\n\
             D\tConfig/\tLoadShort\tx\n",
        );
        let pick = |p: &str| {
            rules
                .candidates(p)
                .map(|s| (s.loaders.join("|"), s.tier, s.key))
        };
        assert_eq!(
            pick("BakedConfig/Config/LevelOutput/HeartDial/HeartDial_Floor_201.bytes"),
            Some((
                "LoadFloor".into(),
                "override",
                "Config/LevelOutput/HeartDial/HeartDial_Floor_".into()
            ))
        );
        assert_eq!(
            pick("BakedConfig/Config/Level/MunicipalChatConfig/F1/MunicipalChatConfig_7.bytes"),
            Some((
                "LoadChat".into(),
                "family",
                "Config/Level/MunicipalChatConfig/F#/MunicipalChatConfig*".into()
            ))
        );
        assert_eq!(
            pick("BakedConfig/Config/Level/NewThing/X1.layout.bytes"),
            Some((
                LAYOUT_LOADER.into(),
                "layout",
                "Config/Level/NewThing/X*.layout".into()
            ))
        );
        assert_eq!(
            pick("BakedConfig/Config/Level/NewThing/X1.bytes"),
            Some(("LoadGraph".into(), "default", "Config/Level/".into()))
        );
        assert_eq!(pick("BakedConfig/Other/X.bytes"), None);
    }

    #[test]
    fn evidence_sets_rule_strength() {
        let cases = [
            ("O", "client xref", Strength::Proven),
            (
                "F",
                "runtime truth RPG.GameCore.LevelGraphConfig",
                Strength::Proven,
            ),
            (
                "F",
                "client BinaryBakeLayoutPath transform",
                Strength::Proven,
            ),
            ("F", "sniff exact 4/4 RPG.GameCore.X", Strength::Sniffed),
            ("F", "dir:Config/A/;sniff:X=3;name:X", Strength::Sniffed),
            (
                "F",
                "dir:Config/ConfigEntity/;name:EntityConfig",
                Strength::Inferred,
            ),
            ("F", "name:HipplenGameMainConfig", Strength::Guessed),
            ("D", "directory default", Strength::Inferred),
        ];
        for (kind, evidence, strength) in cases {
            assert_eq!(
                Strength::from_evidence(kind, evidence),
                strength,
                "{evidence}"
            );
        }
        let rules =
            Rules::parse("F\tConfig/A/B*\tLoadB\tname:B\nD\tConfig/A/\tLoadA\tdirectory default\n");
        let strength = |p: &str| rules.candidates(p).map(|s| s.strength);
        assert_eq!(
            strength("BakedConfig/Config/A/B1.bytes"),
            Some(Strength::Guessed)
        );
        assert_eq!(
            strength("BakedConfig/Config/A/C1.bytes"),
            Some(Strength::Inferred)
        );
        assert_eq!(
            strength("BakedConfig/Config/A/C1.layout.bytes"),
            Some(Strength::Proven)
        );
    }

    #[test]
    fn embedded_rules_load() {
        let rules = Rules::embedded();
        assert!(rules.family_count() > 1000);
        let selection = rules
            .candidates(
                "BakedConfig/Config/Level/Mission/1000101/MissionInfo_1000101.partial.bytes",
            )
            .unwrap();
        assert_eq!(selection.loaders[0], "LoadMainMissionPartialInfoConfig");
        let minigame = rules
            .candidates("BakedConfig/Config/Gameplays/Hipplen/MiniGame/Hipplen_MiniGame_MovingGoods_20101.bytes")
            .unwrap();
        assert_eq!(minigame.strength, Strength::Guessed);
    }
}
