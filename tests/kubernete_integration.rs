use std::pin::pin;
use std::sync::{Arc, mpsc};
use kube::runtime::watcher::Config;
use tokio::sync::Mutex;
use pki_watcher::configuration::KubernetesPkiStoreConfiguration;
use pki_watcher::store::kubernetes_store::KubernetesSecreteWatcher;

pub struct StoreConfiguration {
    pub pki_kubernetes_namespace: String,
    pub pki_kubernetes_secret_name: String,
    pub pki_kubernetes_resource_keys : Vec<String>,
}


impl KubernetesPkiStoreConfiguration for StoreConfiguration {
    fn get_pki_kubernetes_namespace(&self) -> String {
        self.pki_kubernetes_namespace.clone()
    }

    fn get_pki_kubernetes_secret_name(&self) -> String {
        self.pki_kubernetes_secret_name.clone()
    }

    fn get_pki_kubernetes_resource_keys(&self) -> Vec<String> {
        self.pki_kubernetes_resource_keys.clone()
    }
}

#[test]
pub async fn test_kubernetes()  {
    let client = kube::client::Client::try_default().await.unwrap();
    let watcher_config = Config::default();
    let config = StoreConfiguration {
        pki_kubernetes_namespace: "".to_string(),
        pki_kubernetes_secret_name: "".to_string(),
        pki_kubernetes_resource_keys: vec![],
    };
    let store = pin!(KubernetesSecreteWatcher::new(client,watcher_config, &config));
    let (notify_tx, notify_rx) = mpsc::channel();
    store.watch(notify_tx).await.unwrap();

    match notify_rx.recv().unwrap() { (a, mut b) => {
        b.get_mut().merge(a);
    } }
}
