use super::*;

#[tokio::test]
async fn inventory_detects_same_size_changes_to_untracked_payloads() {
    let objects = Arc::new(object_store::memory::InMemory::new());
    let location = Path::from("v1/untracked.json");
    objects
        .put(&location, Bytes::from_static(b"abc").into())
        .await
        .unwrap();
    let repository = DurableRepository {
        pool: PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/unused")
            .unwrap(),
        objects: objects.clone(),
        limits: StorageLimits::default(),
    };
    let mut before = Vec::new();
    repository
        .write_bucket_inventory(&mut before)
        .await
        .unwrap();
    objects
        .put(&location, Bytes::from_static(b"xyz").into())
        .await
        .unwrap();
    let mut after = Vec::new();
    repository.write_bucket_inventory(&mut after).await.unwrap();
    assert_ne!(before, after);
    let record: serde_json::Value = serde_json::from_slice(&after).unwrap();
    assert_eq!(record["key"], "v1/untracked.json");
    assert_eq!(record["sha256"], hex(&Sha256::digest(b"xyz")));
}
