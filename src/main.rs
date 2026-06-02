use std::sync::Arc;

use axum::{
    body::Body as AxumBody,
    extract::{Path, State},
    http::Request,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Router,
};
use leptos::{config::get_configuration, logging::log, prelude::provide_context};
use leptos_axum::{generate_route_list, handle_server_fns_with_context, LeptosRoutes};
use sentry_tower::{NewSentryLayer, SentryHttpLayer};
use tower::ServiceBuilder;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use yral_auth::{
    api::oauth_server_impl::handle_apple_oauth_form_post,
    api::server_impl::{
        handle_oauth_token_grant, handle_oidc_configuration, handle_well_known_jwks, healthz,
    },
    app::{shell, App},
    context::server::{ServerCtx, ServerState},
};

async fn server_fn_handler(
    State(app_state): State<ServerState>,
    _path: Path<String>,
    request: Request<AxumBody>,
) -> impl IntoResponse {
    handle_server_fns_with_context(
        move || {
            provide_context(app_state.ctx.clone());
        },
        request,
    )
    .await
}

async fn leptos_routes_handler(state: State<ServerState>, req: Request<AxumBody>) -> Response {
    let State(app_state) = state.clone();
    let handler = leptos_axum::render_route_with_context(
        app_state.routes.clone(),
        move || {
            provide_context(app_state.ctx.clone());
        },
        move || shell(app_state.leptos_options.clone()),
    );
    handler(state, req).await.into_response()
}

fn server_routes(ctx: Arc<ServerCtx>) -> Router {
    Router::new()
        .route("/oauth/token", post(handle_oauth_token_grant))
        .route("/oauth_callback", post(handle_apple_oauth_form_post))
        .route("/.well-known/jwks.json", get(handle_well_known_jwks))
        .route(
            "/.well-known/openid-configuration",
            get(handle_oidc_configuration),
        )
        .route("/healthz", get(healthz))
        .layer(Extension(ctx))
}

fn setup_sentry_subscriber() {
    tracing_subscriber::registry()
        .with(sentry_tracing::layer())
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

#[tokio::main]
async fn main() {
    let _guard = sentry::init((
        "https://c77631cc9b797bd2c9520d74bc08eaad@sentry.naitik.yral.com/3",
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: Some(
                std::env::var("APP_ENV")
                    .unwrap_or("local".to_owned())
                    .into(),
            ),
            traces_sample_rate: std::env::var("SENTRY_TRACES_SAMPLE_RATE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.5),
            send_default_pii: false, // Keep false, manually add safe data
            attach_stacktrace: true,
            before_send: Some(yral_auth::middleware::sentry_scrub::create_before_send()),
            before_send: Some(yral_auth::middleware::sentry_scrub::create_before_send()),
            ..Default::default()
        },
    ));

    setup_sentry_subscriber();

    let conf = get_configuration(None).unwrap();
    let addr = conf.leptos_options.site_addr;
    let leptos_options = conf.leptos_options;
    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);

    dotenvy::dotenv().ok();

    let ctx = Arc::new(ServerCtx::new().await);

    // Start background JWK refresh task for Google OAuth
    #[cfg(feature = "google-oauth")]
    ctx.start_jwk_refresh_task();

    let app_state = ServerState {
        leptos_options,
        routes: routes.clone(),
        ctx: ctx.clone(),
    };

    let sentry_tower_layer = ServiceBuilder::new()
        .layer(NewSentryLayer::new_from_top())
        .layer(SentryHttpLayer::with_transaction());

    let governor_conf = GovernorConfigBuilder::default()
        .per_second(5)
        .burst_size(10)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .unwrap();

    let app = Router::new()
        .route(
            "/api/{*fn_name}",
            get(server_fn_handler).post(server_fn_handler),
        )
        .leptos_routes_with_handler(routes, get(leptos_routes_handler))
        .layer(GovernorLayer::new(governor_conf))
        .fallback(leptos_axum::file_and_error_handler::<ServerState, _>(shell))
        .with_state(app_state)
        .merge(server_routes(ctx))
        .layer(axum::middleware::from_fn(
            yral_auth::middleware::http_logging_middleware,
            yral_auth::middleware::http_logging_middleware,
        )) // HTTP logging before Sentry
        .layer(sentry_tower_layer);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    log!("listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
