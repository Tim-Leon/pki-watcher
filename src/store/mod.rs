#[cfg(feature = "file-store")]
pub mod file_store;
#[cfg(feature = "kube-store")]
pub mod kubernetes_store;
#[cfg(feature = "spiffe-store")]
pub mod spiffe_store;

#[cfg(test)]
mod tests {
    use std::pin::pin;

    use kube::runtime::watcher::Config;
    use kubernetes_mock::make_mocker;

    use crate::configuration::KubernetesPkiStoreConfiguration;
    use crate::store::kubernetes_store::KubernetesSecreteWatcher;

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
    #[tokio::test]
    async fn kubernetes_store_test() {
        let (client, mut mocker) = make_mocker();
        
        mocker.run().await.unwrap();
        //let client = kube::client::Client::try_default().await.unwrap();

        let watcher_config = Config::default();
        let config = StoreConfiguration {
            pki_kubernetes_namespace: "".to_string(),
            pki_kubernetes_secret_name: "".to_string(),
            pki_kubernetes_resource_keys: vec![],
        };
        let store = pin!(KubernetesSecreteWatcher::new(client,watcher_config, &config));
        //let (notify_tx, notify_rx) = mpsc::channel();
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(32);
        store.watch(notify_tx).await.unwrap();

        match notify_rx.recv().await.unwrap() { (a, b) => {
            b.get_mut().merge(&mut a);
        } }
    }



}
