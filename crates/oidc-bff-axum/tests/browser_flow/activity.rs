use super::*;

struct Fixture {
    _provider: TestProvider,
    identity: IdentityApplication,
    app: Router,
    sessions: MemoryStore,
    cookie: String,
    id: Id,
    csrf: String,
}

impl Fixture {
    async fn login() -> Self {
        let provider = TestProvider::start_with_distinct_backchannel().await;
        let configuration = provider.configuration();
        let identity = IdentityApplication::discover(configuration.clone())
            .await
            .unwrap();
        let sessions = MemoryStore::default();
        let app = IdentityHttpApplication::new(identity.clone())
            .with_session_store(Arc::new(sessions.clone()))
            .router()
            .layer(IdentitySessionLayer::new(configuration.cookie()).store(sessions.clone()));
        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/login?reauthenticate=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let pending = session_cookie(login.headers()).unwrap();
        let url = url::Url::parse(login.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        let query = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
        assert_eq!(query["prompt"], "login");
        assert_eq!(query["max_age"], "0");
        *provider.nonce.lock().await = Some(query["nonce"].clone());
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("code", "test-code")
            .append_pair("state", &query["state"])
            .finish();
        let callback = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/auth/callback?{query}"))
                    .header(header::COOKIE, pending)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(callback.status(), StatusCode::SEE_OTHER);
        let cookie = session_cookie(callback.headers()).unwrap();
        let id = cookie.split_once('=').unwrap().1.parse().unwrap();
        let projection = Self::read(&app, Some(&cookie)).await;
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        assert!((43_198..=43_200).contains(&(projection.expires_at_epoch_seconds.unwrap() - now)));
        assert!(
            (3_598..=3_600)
                .contains(&(projection.inactivity_expires_at_epoch_seconds.unwrap() - now))
        );
        Self {
            _provider: provider,
            identity,
            app,
            sessions,
            cookie,
            id,
            csrf: projection.anti_forgery_token.unwrap(),
        }
    }

    async fn read(app: &Router, cookie: Option<&str>) -> IdentitySession {
        let mut request = Request::builder().uri("/auth/session");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie_age = response.headers().get(header::SET_COOKIE).map(|value| {
            tower_sessions::cookie::Cookie::parse(value.to_str().unwrap())
                .unwrap()
                .max_age()
                .unwrap()
                .whole_seconds()
        });
        let projection: IdentitySession =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        if let Some(deadline) = projection.inactivity_expires_at_epoch_seconds {
            let remaining = deadline as i64 - time::OffsetDateTime::now_utc().unix_timestamp();
            assert!((remaining - cookie_age.unwrap()).abs() <= 1);
        }
        projection
    }

    fn activity(&self, origin: &str, csrf: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/auth/session/activity")
            .header(header::COOKIE, &self.cookie)
            .header(header::ORIGIN, origin)
            .header("x-anti-forgery-token", csrf)
            .body(Body::empty())
            .unwrap()
    }
}

#[tokio::test]
async fn human_activity_renews_cookie_and_record_but_polling_and_provider_refresh_do_not() {
    let f = Fixture::login().await;
    let now = time::OffsetDateTime::now_utc();
    let mut record = f.sessions.load(&f.id).await.unwrap().unwrap();
    let absolute = record.data["identity.authenticated"]["expires_at_epoch_seconds"].clone();
    record.expiry_date = now + time::Duration::seconds(120);
    record.data.get_mut("identity.authenticated").unwrap()["identity_expires_at_epoch_seconds"] =
        json!(now.unix_timestamp() + 1);
    f.sessions.save(&record).await.unwrap();
    let projected = Fixture::read(&f.app, Some(&f.cookie)).await;
    assert_eq!(
        projected.inactivity_expires_at_epoch_seconds,
        Some(record.expiry_date.unix_timestamp() as u64)
    );
    assert_eq!(
        f.sessions.load(&f.id).await.unwrap().unwrap().expiry_date,
        record.expiry_date
    );

    let cached_browser = Session::new(Some(f.id), Arc::new(f.sessions.clone()), None);
    let user = f
        .identity
        .authenticated_user(&cached_browser)
        .await
        .unwrap();
    let live = f
        .identity
        .live_browser_login(
            &cached_browser,
            &user,
            Arc::new(f.sessions.clone()),
            Default::default(),
        )
        .await
        .unwrap();
    live.current().await.unwrap();
    let refreshed = f.sessions.load(&f.id).await.unwrap().unwrap();
    assert_eq!(refreshed.expiry_date, record.expiry_date);
    assert_eq!(
        refreshed.data["identity.authenticated"]["refresh_token"],
        "refresh-token-2"
    );

    for (origin, csrf) in [
        ("https://attacker.example", f.csrf.as_str()),
        ("http://127.0.0.1:3000", "wrong"),
    ] {
        let response = f
            .app
            .clone()
            .oneshot(f.activity(origin, csrf))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(session_cookie(response.headers()).is_none());
        assert_eq!(
            f.sessions.load(&f.id).await.unwrap().unwrap().expiry_date,
            record.expiry_date
        );
    }
    let response = f
        .app
        .clone()
        .oneshot(f.activity("http://127.0.0.1:3000", &f.csrf))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let cookie = tower_sessions::cookie::Cookie::parse(
        response.headers()[header::SET_COOKIE].to_str().unwrap(),
    )
    .unwrap();
    assert!((3_598..=3_600).contains(&cookie.max_age().unwrap().whole_seconds()));
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(
        cookie.same_site(),
        Some(tower_sessions::cookie::SameSite::Lax)
    );
    assert_eq!(cookie.path(), Some("/"));
    assert_eq!(session_cookie(response.headers()).unwrap(), f.cookie);
    let projection: IdentitySession =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let renewed = f.sessions.load(&f.id).await.unwrap().unwrap();
    assert_eq!(
        projection.inactivity_expires_at_epoch_seconds,
        Some(renewed.expiry_date.unix_timestamp() as u64)
    );
    assert!(renewed.expiry_date >= now + time::Duration::seconds(3_598));
    assert_eq!(
        renewed.data["identity.authenticated"]["expires_at_epoch_seconds"],
        absolute
    );
    assert_eq!(
        renewed.data["identity.authenticated"]["refresh_token"],
        "refresh-token-2"
    );
    assert_eq!(
        Fixture::read(&f.app, None).await.status,
        AuthenticationStatus::Anonymous
    );
}

#[tokio::test]
async fn renewal_is_capped_by_absolute_expiry_and_cannot_revive_expired_or_deleted_sessions() {
    let f = Fixture::login().await;
    let mut record = f.sessions.load(&f.id).await.unwrap().unwrap();
    let absolute = time::OffsetDateTime::now_utc().unix_timestamp() + 30;
    record.data.get_mut("identity.authenticated").unwrap()["expires_at_epoch_seconds"] =
        json!(absolute);
    f.sessions.save(&record).await.unwrap();
    let response = f
        .app
        .clone()
        .oneshot(f.activity("http://127.0.0.1:3000", &f.csrf))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = tower_sessions::cookie::Cookie::parse(
        response.headers()[header::SET_COOKIE].to_str().unwrap(),
    )
    .unwrap();
    assert!(cookie.max_age().unwrap().whole_seconds() <= 30);
    assert_eq!(
        f.sessions
            .load(&f.id)
            .await
            .unwrap()
            .unwrap()
            .expiry_date
            .unix_timestamp(),
        absolute
    );

    // A still-present browser cookie must not bypass either server deadline.
    for idle_expired in [true, false] {
        let mut expired = record.clone();
        if idle_expired {
            expired.expiry_date = time::OffsetDateTime::UNIX_EPOCH;
        } else {
            expired.data.get_mut("identity.authenticated").unwrap()["expires_at_epoch_seconds"] =
                json!(1);
        }
        f.sessions.save(&expired).await.unwrap();
        let response = f
            .app
            .clone()
            .oneshot(f.activity("http://127.0.0.1:3000", &f.csrf))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            Fixture::read(&f.app, Some(&f.cookie)).await.status,
            AuthenticationStatus::Anonymous
        );
    }
    f.sessions.save(&record).await.unwrap();
    let browser = Session::new(Some(f.id), Arc::new(f.sessions.clone()), None);
    let (renewal, logout) = tokio::join!(
        f.app
            .clone()
            .oneshot(f.activity("http://127.0.0.1:3000", &f.csrf)),
        f.identity.logout(&browser, &f.csrf),
    );
    assert!(matches!(
        renewal.unwrap().status(),
        StatusCode::OK | StatusCode::UNAUTHORIZED
    ));
    logout.unwrap();
    assert!(f.sessions.load(&f.id).await.unwrap().is_none());
    assert_eq!(
        f.app
            .clone()
            .oneshot(f.activity("http://127.0.0.1:3000", &f.csrf))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
