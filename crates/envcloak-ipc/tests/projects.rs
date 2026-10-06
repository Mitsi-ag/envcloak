//! M3-04 strict wire shapes and value-free debug output.
#![allow(clippy::unwrap_used)]

use envcloak_ipc::proto::{ProjectsListParams, Role, required_role};
use envcloak_ipc::view::{
    ProjectBindingView, ProjectCursor, ProjectView, ProjectsView, RefUnsetView,
};

#[test]
fn projects_wire_is_strict_and_debug_never_prints_input() {
    assert_eq!(required_role("projects.list"), Role::Client);
    assert!(
        serde_json::from_str::<ProjectsListParams>("{}")
            .unwrap()
            .after
            .is_none()
    );
    for text in [
        r#"{"extra":true}"#,
        r#"{"after":{"last_seen":0,"id":"x","extra":true}}"#,
        r#"{"after":{"last_seen":-1,"id":"x"}}"#,
        r#"{"after":{"last_seen":1.5,"id":"x"}}"#,
        r#"{"after":{"last_seen":0,"id":[]}}"#,
        r#"{"after":[]}"#,
        r#"{"after":null,"after":null}"#,
    ] {
        assert!(serde_json::from_str::<ProjectsListParams>(text).is_err());
    }
    let marker = format!("input-{}", envcloak_testkit::fresh_seed());
    let cursor = ProjectCursor {
        last_seen: 1,
        id: marker.clone(),
    };
    let binding = ProjectBindingView {
        env_name: marker.clone(),
        reference: marker.clone(),
    };
    let row = ProjectView {
        dir: marker.clone(),
        manifest_sha256: marker.clone(),
        bindings: vec![binding.clone()],
        last_seen_secs: 1,
    };
    let page = ProjectsView {
        projects: vec![row.clone()],
        next: Some(cursor.clone()),
    };
    let params = ProjectsListParams {
        after: Some(cursor.clone()),
    };
    let removed = RefUnsetView {
        profile: Some(marker.clone()),
        env_name: marker.clone(),
        reference: marker.clone(),
    };
    for debug in [
        format!("{cursor:?}"),
        format!("{binding:?}"),
        format!("{row:?}"),
        format!("{page:?}"),
        format!("{params:?}"),
        format!("{removed:?}"),
    ] {
        assert!(!debug.contains(&marker));
    }
    let encoded = serde_json::to_vec(&page).unwrap();
    assert_eq!(
        serde_json::from_slice::<ProjectsView>(&encoded).unwrap(),
        page
    );
}
