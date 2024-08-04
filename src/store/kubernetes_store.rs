use core::slice::SlicePattern;
use std::io::Cursor;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::{Arc};

use futures::stream::TryStreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::Api;
use kube::Client;
use kube::ResourceExt;
use kube::runtime::watcher::Config;
use kube::runtime::WatchStreamExt;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use crate::configuration::KubernetesPkiStoreConfiguration;
use crate::ParsedPkiData;
use crate::parser::parse::{KubernetesError, parse_kubernetes_secret, PkiParser};
use crate::parser::PemParser;

pub struct KubernetesSecreteWatcherConfigurationInner {
    pub pki_kubernetes_namespace: String,
    pub get_pki_kubernetes_secret_name: String,
    pub get_pki_kubernetes_resource_keys: Vec<String>,
}

pub struct KubernetesSecreteWatcher<'a> {
    client: Client,
    watcher_config: Config,
    config: KubernetesSecreteWatcherConfigurationInner,
    parser: PkiParser,
    parsed_pki_data: Arc<Mutex<ParsedPkiData<'a>>>,
}



#[derive(Debug)]
pub struct ResourceInformation<'a> {
    // The name of the resource that is being parsed. Could be kubernetes resource name, or filename depends on usage.
    pub name: String,
    // The data that was just parsed. Can be compared in the event channel against the current state.
    pub parsed_pki_data: ParsedPkiData<'a>,
}

/// .
/// namespace and secret_name are what you set it in the yaml file. hence up to the user
/// # Errors
///
/// This function will return an error if .
pub async fn load_secrets_from_kubernetes_resource(
    client: Client,
    namespace: &str,
    secret_name: &str,
) -> Result<Secret, KubernetesError> {
    // Create an API instance for Secrets in the specified namespace
    let secrets = kube::Api::namespaced(client, namespace);
    // Retrieve the Secret
    let secret: Secret = secrets.get(secret_name).await.unwrap();

    Ok(secret)
}
impl KubernetesSecreteWatcher<'_> {

    pub fn new(
        client: Client,
        watcher_config: Config,
        config: &impl KubernetesPkiStoreConfiguration,
    ) -> Self {
        Self {
            client,
            watcher_config,
            config: KubernetesSecreteWatcherConfigurationInner {
                pki_kubernetes_namespace: config.get_pki_kubernetes_namespace(),
                get_pki_kubernetes_secret_name: config.get_pki_kubernetes_secret_name(),
                get_pki_kubernetes_resource_keys: config.get_pki_kubernetes_resource_keys(),
            },
            parser: PkiParser::new(),
            parsed_pki_data: Default::default(),
        }
    }
}
#[derive(thiserror::Error, Debug)]
pub enum KubernetesSecretWatcherError {
    #[error(transparent)]
    WatcherError(#[from] kube::runtime::watcher::Error),
}

//#[async_trait]

/*
Watch over resource,
Template Parser, make it modular.
New updates send events with data of the old and new parsed version of data.
*/

impl<'a> KubernetesSecreteWatcher<'a> {
    ///
    ///
    /// # Arguments
    ///
    /// * `notify_tx`: A stream current PKI data and neweley parsed PKI data. It's up to the even stream of how to handle newly retrieved data. The default behavour which should be implemented by the stream is to simpely add the data.
    ///
    ///
    /// returns: Result<(), KubernetesSecreteWatcherError>
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    pub async fn watch<'b>(
        self: Pin<&'b mut Self>,
        notify_tx: mpsc::Sender<(ParsedPkiData<'b>, Arc<Mutex<ParsedPkiData<'a>>>)>
    ) -> Result<(), KubernetesSecretWatcherError> {
        let api: Api<Secret> = Api::namespaced(
            self.client.clone(),
            self.config.pki_kubernetes_namespace.as_str(),
        );
        let watcher_config = self.watcher_config.clone();
        let client = self.client.clone();
        let parser = self.parser.clone();
        let parsed_pki_data = self.parsed_pki_data.clone();

        let watcher = kube::runtime::watcher(api, watcher_config)
            .applied_objects()
            .try_for_each(|p| {
                let mut parser = parser.clone();
                let notify_tx = notify_tx.clone();
                let parsed_pki_data = parsed_pki_data.clone();
                async move {
                    tracing::info!("PKI resource: {}, in namespace: {}", p.name_any(), p.namespace().unwrap_or_default());
                    if let Some(data) = p.data.and_then(|d| d.get("data").cloned()) {
                        let reader = Cursor::new(data.0);
                        let mut temp_parsed_pki_data = ParsedPkiData::default();
                        parser.parse_pem(&mut temp_parsed_pki_data, reader).unwrap();
                        notify_tx.send((temp_parsed_pki_data, parsed_pki_data.clone())).await.unwrap()
                    }
                    Ok(())
                }
            });

        watcher.await.map_err(KubernetesSecretWatcherError::from)
    }
    pub async fn retrieve(&mut self) -> Result<(), KubernetesSecretWatcherError> {
        use std::borrow::BorrowMut;
        let client = Client::try_default().await.unwrap();

        let secret = load_secrets_from_kubernetes_resource(
            client.clone(),
            self.config.pki_kubernetes_namespace.as_str(),
            self.config.get_pki_kubernetes_secret_name.as_str(),
        )
        .await
        .unwrap();
        for key in &self.config.get_pki_kubernetes_resource_keys {
            let cursor = parse_kubernetes_secret(&secret, key.as_str()).unwrap();
            let mut temp_parsed_pki = self.parsed_pki_data.deref().lock().await;
            self.parser
                .parse_pem(temp_parsed_pki.borrow_mut(), cursor)
                .unwrap()

        }
        Ok(())
    }

    pub fn get_parsed_pki_data(&'a self) -> Arc<Mutex<ParsedPkiData<'a>>> {
        self.parsed_pki_data.clone()
    }
}
