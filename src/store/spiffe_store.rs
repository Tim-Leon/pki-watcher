// use crate::parser::parse::{Identities, PkiParser};
// use crate::ParsedPkiData;
// use futures::StreamExt;
// use rustls::internal::msgs::codec::Codec;
// use rustls_pki_types::CertificateDer;
// use spiffe::error::GrpcClientError;
// use spiffe::svid::x509::X509Svid;
// use spiffe::workload_api::client::WorkloadApiClient;
// use std::sync::mpsc;
// use std::sync::mpsc::Receiver;
//
// pub struct SpiffePkiConfig {
//     pub spiffe_path: String,
// }
//
// pub struct SpiffeStore<'a> {
//     client: WorkloadApiClient,
//     config: SpiffePkiConfig,
//     identities: Identities<'a>,
//     certificate_svid: Vec<X509Svid>,
//     parser: PkiParser,
// }
// #[derive(thiserror::Error, Debug)]
// pub enum SpiffeWatcherRetrieverError {
//     #[error(transparent)]
//     GrpcClientError(#[from] GrpcClientError),
// }
// impl SpiffeStore<'_> {
//     async fn watch(&mut self) -> Result<(), SpiffeWatcherRetrieverError> {
//         let mut stream = self.client.stream_x509_contexts().await.unwrap();
//         tokio::spawn(async move {
//             while let Some(x509_context_update) = stream.next().await {
//                 match x509_context_update {
//                     Ok(update) => {
//                         let a = update.svids();
//                         let b = update.bundle_set();
//                         a[0].private_key();
//                         a[0].cert_chain();
//                     }
//                     Err(err) => {}
//                 }
//             }
//         });
//
//         Ok(())
//     }
//
//     async fn retrieve(&mut self) -> Result<(), SpiffeWatcherRetrieverError> {
//         let mut client = WorkloadApiClient::new_from_path(self.config.spiffe_path.as_str())
//             .await
//             .unwrap();
//         self.certificate_svid = client.fetch_all_x509_svids().await?;
//         for svid in &self.certificate_svid {
//             self.parser
//                 .parse_x509_svid(&mut self.identities, svid)
//                 .unwrap();
//         }
//         Ok(())
//     }
// }
