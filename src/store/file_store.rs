use crate::parser::parse::PkiParser;
use crate::ParsedPkiData;
use notify::event::ModifyKind;
use notify::{Config, Event, EventHandler, EventKind, INotifyWatcher, RecommendedWatcher, RecursiveMode, Watcher};
use std::io::Cursor;
use std::mem::take;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::watch::Receiver;
use tokio::sync::{mpsc, Mutex};
use crate::store::{PkiStore, PkiWatcherEventHandler};

#[derive(thiserror::Error, Debug)]
pub enum FileStoreError {}


pub trait PkiFileStoreWatchers {
    type Error;
    fn watch(&mut self, event_handler: &mut impl PkiWatcherEventHandler) -> Result<(), Self::Error>;
}

pub trait PkiFileStoreRetrievers {
    type Error;
    async fn retrieve(&mut self) -> Result<(), Self::Error>;
}

pub struct FileStore<'a> {
    path: PathBuf,
    watcher: Option<INotifyWatcher>,
    parser: PkiParser,
    parsed_pki_data: Arc<Mutex<ParsedPkiData<'a>>>,
}

impl PkiFileStoreRetrievers for FileStore<'_> {
    type Error = FileStoreError;
    async fn retrieve(&mut self) -> Result<(), Self::Error> {
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

impl PkiFileStoreWatchers for FileStore<'_> {
    type Error = FileStoreError;

    fn watch(&mut self, event_handler: &mut impl PkiWatcherEventHandler) -> Result<(), Self::Error> {
        use std::borrow::BorrowMut;
        let path = self.path.clone();
        RecommendedWatcher::new(&event_handler, Config::default())
            .unwrap()
            .watch(path.as_path(), RecursiveMode::Recursive)
            .unwrap();
        Ok(())
    }
}


pub struct DefaultPkiFileStoreEventHandling {
    pub path: String,
    
}
impl PkiWatcherEventHandler for DefaultPkiFileStoreEventHandling {
    type Event = Event;
    fn handle_event(&mut self, event: Self::Event, store: impl PkiStore) {
        match event {
            Event { kind, paths, attrs } => {
                match kind {
                    EventKind::Any => {}
                    EventKind::Access(_) => {}
                    EventKind::Create(_) => {}
                    EventKind::Modify(_) => {}
                    EventKind::Remove(_) => {}
                    EventKind::Other => {}
                }
            }
        }
    }
}

impl EventHandler for DefaultPkiFileStoreEventHandling {
    fn handle_event(&mut self, event: notify::Result<Event>)  {
        use std::borrow::BorrowMut;
        futures::executor::block_on(async || {
            let path = self.path.clone();
            let kind = event.unwrap().kind;

            match kind {
                EventKind::Any => {}
                EventKind::Access(_) => {}
                EventKind::Create(_) => {}
                EventKind::Modify(modification) => {
                    match modification {
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
                    }
                }
                EventKind::Remove(_) => {}
                EventKind::Other => {}
            }
        })
    }
}

