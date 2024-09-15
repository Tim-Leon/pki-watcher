use crate::parser::parse::PkiParser;
use crate::store::{PkiStore, PkiWatcherEventHandler};
use crate::ParsedPkiData;
use notify::event::ModifyKind;
use notify::{
    Config, Event, EventHandler, EventKind, INotifyWatcher, RecommendedWatcher, RecursiveMode,
    Watcher,
};
use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::Mutex;


#[derive(thiserror::Error, Debug)]
pub enum FileStoreError {}

pub trait PkiFileStoreWatchers {
    type Error;
    async fn watch<E: std::marker::Send + 'static>(
        &mut self,
        event_handler: &mut Box<E>,
    ) -> Result<(), Self::Error>;
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
struct EventHandlerAdapter<E: Send> {
    pki_event_handler: Box<dyn PkiWatcherEventHandler<E>>,
}

impl<E: std::marker::Send + 'static> EventHandler for EventHandlerAdapter<E> {
    fn handle_event(&mut self, event: notify::Result<Event>) {
        let event = event.unwrap();
        self.pki_event_handler.handle_event(event);
    }
}
impl PkiFileStoreWatchers for FileStore<'_> {
    type Error = FileStoreError;

    async fn watch<E: std::marker::Send + 'static>(
        self: &mut Self,
        watcher_event: impl PkiWatcherEventHandler<E> + 'static,
    ) -> Result<(), Self::Error> {
        let path = self.path.clone();
        let adapter = EventHandlerAdapter { pki_event_handler: Box::new(watcher_event) };
        RecommendedWatcher::new(adapter, Config::default())
            .unwrap()
            .watch(path.as_path(), RecursiveMode::Recursive)
            .unwrap();
        Ok(())
    }
}

pub struct DefaultPkiFileStoreEventHandling<'a> {
    pub path: String,
    pub parsed_pki_data: Arc<Mutex<ParsedPkiData<'a>>>,
    pub parser: PkiParser,
}

impl<E> PkiWatcherEventHandler<E> for DefaultPkiFileStoreEventHandling<'_> where E: notify::event::Event {
    fn handle_event(&mut self, event: E) {
        futures::executor::block_on(async || {
            let path = self.path.clone();
            let kind = event.kind;

            match kind {
                EventKind::Any => {}
                EventKind::Access(_) => {}
                EventKind::Create(_) => {}
                EventKind::Modify(modification) => match modification {
                    ModifyKind::Any => {}

                    ModifyKind::Data(_) => {
                        let reader = tokio::fs::read(path).await.unwrap();
                        let is_cleared_on_update = false;
                        let cursor = Cursor::new(reader);
                        let mut temp_parsed_pki_data = self.parsed_pki_data.deref().lock().await;
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
            }
        })
    }
}

impl EventHandler for DefaultPkiFileStoreEventHandling<'static> {
    fn handle_event(&mut self, event: notify::Result<Event>) {
        use PkiWatcherEventHandler;
        let event = event.unwrap();
        PkiWatcherEventHandler::handle_event(self, event);
    }
}
