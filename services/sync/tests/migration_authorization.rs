//! Execute migration failure modes inside rolled-back, isolated schemas.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL; creates only transactional fixtures"]
async fn legacy_root_migration_never_promotes_a_surviving_credential() {
    let pool =
        sqlx::PgPool::connect(&std::env::var("DATABASE_URL").expect("disposable DATABASE_URL"))
            .await
            .unwrap();
    // Offsets are seconds from each vault's explicit creation timestamp.
    // None omits the device, so missing evidence includes an empty vault.
    for (case, root_active, root_offset, survivor_offset, should_succeed) in [
        ("active root", Some(true), 0, Some(60), true),
        (
            "survivor predates active root",
            Some(true),
            0,
            Some(-60),
            true,
        ),
        ("revoked root", Some(false), 0, Some(60), false),
        (
            "survivor predates revoked root",
            Some(false),
            0,
            Some(-60),
            false,
        ),
        ("ambiguous active roots", Some(true), 0, Some(0), false),
        (
            "ambiguous root includes revoked device",
            Some(false),
            0,
            Some(0),
            false,
        ),
        ("no timestamp match", Some(true), 1, Some(60), false),
        ("missing original device", None, 0, Some(-60), false),
        ("vault without devices", None, 0, None, false),
    ] {
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE SCHEMA foliora_migration_fixture; SET LOCAL search_path = foliora_migration_fixture;")
            .execute(&mut *tx).await.unwrap();
        sqlx::raw_sql(include_str!("../migrations/0001_initial.sql"))
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO vaults(vault_id,epoch,quota_bytes,created_at) VALUES('fixture',1,1024,'2026-01-01T00:00:00Z'),('control',1,1024,'2026-01-01T00:00:00Z')")
            .execute(&mut *tx)
            .await
            .unwrap();
        // A valid second vault ensures evidence is checked independently per vault.
        sqlx::query("INSERT INTO devices(vault_id,device_id,record,token_hash,created_at) VALUES('control','control-root','{}',$1,'2026-01-01T00:00:00Z')")
            .bind(vec![4_u8; 32])
            .execute(&mut *tx).await.unwrap();
        if let Some(active) = root_active {
            sqlx::query("INSERT INTO devices(vault_id,device_id,record,token_hash,active,created_at) VALUES('fixture','original','{}',$1,$2,'2026-01-01T00:00:00Z'::timestamptz + $3::int * interval '1 second')")
                .bind(active.then(|| vec![1_u8; 32])).bind(active).bind(root_offset)
                .execute(&mut *tx).await.unwrap();
        }
        if let Some(offset) = survivor_offset {
            sqlx::query("INSERT INTO devices(vault_id,device_id,record,token_hash,active,created_at) VALUES('fixture','survivor','{}',$1,true,'2026-01-01T00:00:00Z'::timestamptz + $2::int * interval '1 second')")
                .bind(vec![2_u8; 32]).bind(offset)
                .execute(&mut *tx).await.unwrap();
        }
        sqlx::raw_sql("SAVEPOINT before_migration")
            .execute(&mut *tx)
            .await
            .unwrap();
        let result = sqlx::raw_sql(include_str!("../migrations/0005_device_authorizations.sql"))
            .execute(&mut *tx)
            .await;
        assert_eq!(result.is_ok(), should_succeed, "{case}: {result:?}");
        if should_succeed {
            let roots: Vec<(String, String)> = sqlx::query_as(
                "SELECT vault_id,device_id FROM devices WHERE is_root ORDER BY vault_id",
            )
            .fetch_all(&mut *tx)
            .await
            .unwrap();
            assert_eq!(
                roots,
                [
                    ("control".into(), "control-root".into()),
                    ("fixture".into(), "original".into())
                ],
                "{case}"
            );
            let survivor: (bool, bool, bool) = sqlx::query_as("SELECT active,is_root,authorization_grant IS NULL FROM devices WHERE vault_id='fixture' AND device_id='survivor'")
                .fetch_one(&mut *tx).await.unwrap();
            assert_eq!(survivor, (true, false, true), "{case}");
            // An old binary cannot omit explicit root/authorization accounting.
            let error = sqlx::query("INSERT INTO devices(vault_id,device_id,record,token_hash) VALUES('fixture','old-writer','{}',$1)")
                .bind(vec![3_u8; 32]).execute(&mut *tx).await.unwrap_err();
            let database_error = error.as_database_error().unwrap();
            assert_eq!(database_error.code().as_deref(), Some("23502"), "{case}");
            assert_eq!(
                database_error
                    .downcast_ref::<sqlx::postgres::PgDatabaseError>()
                    .column(),
                Some("is_root"),
                "{case}"
            );
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                error.as_database_error().unwrap().code().as_deref(),
                Some("P0001"),
                "{case}"
            );
            assert!(
                error
                    .to_string()
                    .contains("Cannot migrate missing, revoked, or ambiguous legacy root evidence"),
                "{case}: {error}"
            );
        }
        // Roll back the entire migration, including its DDL and any root marks.
        sqlx::raw_sql("ROLLBACK TO SAVEPOINT before_migration")
            .execute(&mut *tx)
            .await
            .unwrap();
        let migrated_columns: i64 = sqlx::query_scalar("SELECT count(*) FROM information_schema.columns WHERE table_schema='foliora_migration_fixture' AND table_name='devices' AND column_name IN ('is_root','authorization_grant')")
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(migrated_columns, 0, "{case}");
        tx.rollback().await.unwrap();
    }
    pool.close().await;
}
