pub trait KubernetesPkiStoreConfiguration {
    /// The kubernetes namespace
    fn get_pki_kubernetes_namespace(&self) -> String;
    /// The secrete name
    fn get_pki_kubernetes_secret_name(&self) -> String;
    /// What resources in the secrete to load
    fn get_pki_kubernetes_resource_keys(&self) -> Vec<String>;
}

pub trait FilePkiStoreConfiguration {
    fn get_file_path(&self) -> String;
}

pub trait SpiffePkiStoreConfiguration {
    fn get_spiffe_path(&self) -> String;
}
