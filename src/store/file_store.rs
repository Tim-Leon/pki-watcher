/*use crate::parser::parse::PkiParser;
use crate::ParsedPkiData;
use notify::event::ModifyKind;
use notify::{
    Config, Event, EventKind, INotifyWatcher, RecommendedWatcher, RecursiveMode, Watcher,
};
use std::io::Cursor;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;

pub struct FileStore<'a> {
    path: PathBuf,
    watcher: Option<INotifyWatcher>,
    parser: PkiParser,
    parsed_pki_data: Arc<Mutex<ParsedPkiData<'a>>>,
}
#[derive(thiserror::Error, Debug)]
pub enum FileStoreError {}
impl FileStore<'_> {
    async fn watch(&mut self) -> Result<(), FileStoreError> {
        use std::borrow::BorrowMut;
        let path = self.path.clone();
        RecommendedWatcher::new(
            move |res: Result<Event, _>| {
                futures::executor::block_on(async {
                    match &res.unwrap().kind {
                        EventKind::Any => {}
                        EventKind::Access(_) => {}
                        EventKind::Create(_) => {}
                        EventKind::Modify(modification) => match modification {
                            ModifyKind::Any => {}
                            ModifyKind::Data(_) => {
                                let reader = tokio::fs::read(path).await.unwrap();
                                let is_cleared_on_update = false;
                                let cursor = Cursor::new(reader);
                                let mut temp_parsed_pki_data =
                                    self.parsed_pki_data.deref().lock().await;
                                if !is_cleared_on_update {
                                    self.parser
                                        .parse_pem(temp_parsed_pki_data.borrow_mut(), cursor)
                                        .unwrap();
                                }

                            }
                            ModifyKind::Metadata(_) => {}
                            ModifyKind::Name(_) => {}
                            ModifyKind::Other => {}
                        },
                        EventKind::Remove(_) => {}
                        EventKind::Other => {}
                    };
                    Ok(())
                })
            },
            Config::default(),
        )
        .unwrap()
        .watch(self.path.clone().as_path(), RecursiveMode::Recursive)
        .unwrap();
        Ok(())
    }

    async fn retrieve(&mut self) -> Result<(), FileStoreError> {
        let f = File::open(self.path.clone()).await.unwrap();
        let reader = BufReader::new(f);
        let cursor = Cursor::new(reader.buffer());
        let mut temp_parsed_pki = self.parsed_pki_data.deref().lock().await;
        self.parser
            .parse_pem(temp_parsed_pki.deref_mut(), cursor)
            .unwrap();
        Ok(())
    }
}
*/