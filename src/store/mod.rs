use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use crate::ParsedPkiData;
use crate::store::kubernetes_store::KubernetesSecretWatcherError;

#[cfg(feature = "file-store")]
pub mod file_store;
#[cfg(feature = "kube-store")]
pub mod kubernetes_store;
#[cfg(feature = "spiffe-store")]
pub mod spiffe_store;


pub trait PkiStore {

}

pub trait PkiWatcherEventHandler {
    type Event;
    fn handle_event(&mut self, event: Self::Event, store: impl PkiStore);
}



pub trait PkiWatchers<'a> {
    type Error;

    async fn watch<'b>(
        self: &mut self,
        watcher_event: &mut impl PkiWatcherEventHandler,
    ) -> Result<(), Self::Error>;
}

pub trait PkiRetrievers {
    type Error;
     async fn retrieve(&mut self) -> Result<(), Self::Error>;
}


#[cfg(test)]
mod tests {
    use std::pin::pin;

    use kube::runtime::watcher::Config;
    //use kubernetes_mock::make_mocker;

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
        //let (client, mut mocker) = make_mocker();
        //
        //mocker.run().await.unwrap();
        ////let client = kube::client::Client::try_default().await.unwrap();
//
        //let watcher_config = Config::default();
        //let config = StoreConfiguration {
        //    pki_kubernetes_namespace: "".to_string(),
        //    pki_kubernetes_secret_name: "".to_string(),
        //    pki_kubernetes_resource_keys: vec![],
        //};
        //let store = pin!(KubernetesSecreteWatcher::new(client,watcher_config, &config));
        ////let (notify_tx, notify_rx) = mpsc::channel();
        //let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(32);
        //store.watch(notify_tx).await.unwrap();
//
        //match notify_rx.recv().await.unwrap() { (a, b) => {
        //    b.get_mut().merge(&mut a);
        //} }
    }



}
