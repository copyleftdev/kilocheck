use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use kilo_core::{Observation, SnapshotManifest, Target, independent_group_count};
use proptest::prelude::*;

fn observation(group: impl Into<String>, evidence: impl Into<String>) -> Observation {
    Observation {
        source_id: "property-source".to_owned(),
        classification: "unknown-abuse".to_owned(),
        assertion: "observed".to_owned(),
        confidence: 0.5,
        first_seen: None,
        last_seen: None,
        evidence_hash: evidence.into(),
        independence_group: group.into(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_048))]

    #[test]
    fn every_ipv4_round_trips_through_canonical_text(raw in any::<u32>()) {
        let address = IpAddr::V4(Ipv4Addr::from(raw));
        let target = Target::from(address);
        let reparsed = Target::from_str(&target.value).expect("canonical output must parse");

        prop_assert_eq!(target.version, 4);
        prop_assert_eq!(target, reparsed);
    }

    #[test]
    fn every_ipv6_round_trips_through_canonical_text(raw in any::<u128>()) {
        let address = IpAddr::V6(Ipv6Addr::from(raw));
        let target = Target::from(address);
        let reparsed = Target::from_str(&target.value).expect("canonical output must parse");

        prop_assert_eq!(target.version, 6);
        prop_assert_eq!(target, reparsed);
    }

    #[test]
    fn arbitrary_target_text_never_panics(value in any::<String>()) {
        if let Ok(target) = Target::from_str(&value) {
            let reparsed = Target::from_str(&target.value).expect("accepted target must canonicalize");
            prop_assert_eq!(target, reparsed);
        }
    }

    #[test]
    fn duplicate_evidence_groups_never_increase_independence(
        group in "[a-z][a-z0-9-]{0,31}",
        duplicate_count in 1_usize..128,
    ) {
        let observations = (0..duplicate_count)
            .map(|index| observation(group.clone(), index.to_string()))
            .collect::<Vec<_>>();

        prop_assert_eq!(independent_group_count(&observations), 1);
    }

    #[test]
    fn distinct_evidence_groups_are_counted_once(
        groups in prop::collection::btree_set("[a-z][a-z0-9-]{0,15}", 0..128),
    ) {
        let observations = groups
            .iter()
            .enumerate()
            .map(|(index, group)| observation(group.clone(), index.to_string()))
            .collect::<Vec<_>>();

        prop_assert_eq!(independent_group_count(&observations), groups.len());
    }

    #[test]
    fn valid_manifest_serialization_is_byte_deterministic(
        snapshot_id in "[a-f0-9]{64}",
        created_at in "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
    ) {
        let manifest = SnapshotManifest {
            schema: "kilo.snapshot.v1".to_owned(),
            snapshot_id,
            created_at,
        };

        let first = serde_json::to_vec(&manifest).expect("serializable fixture");
        let second = serde_json::to_vec(&manifest).expect("serializable fixture");
        prop_assert_eq!(&first, &second);
        prop_assert_eq!(SnapshotManifest::parse_json(&first).expect("round trip"), manifest);
    }
}
