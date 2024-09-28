use crate::parser::parse::PkiParser;
use crate::store::{PkiStore, PkiWatcherEventHandler};
use crate::ParsedPkiData;
use notify::event::{EventAttributes, ModifyKind};
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
    type Event;
    async fn watch(
        &mut self,
        event_handler: &mut dyn PkiWatcherEventHandler<Self::Event>,
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

//impl PkiFileStoreWatchers for FileStore<'_> {
//    type Error = FileStoreError;
//
//    type Event = Event;
//    async fn watch(
//        self: &mut Self,
//        handler: impl PkiWatcherEventHandler<Self::Event>,
//    ) -> Result<(), Self::Error> {
//        let path = self.path.clone();
//        RecommendedWatcher::new(handler, Config::default())
//            .unwrap()
//            .watch(path.as_path(), RecursiveMode::Recursive)
//            .unwrap();
//        Ok(())
//    }
//}
//
//impl <F> EventHandler for DefaultPkiFileStoreEventHandling<'_> {
//    fn handle_event(&mut self, event: notify::Result<Event>) {
//        todo!()
//    }
//}
//
//pub struct DefaultPkiFileStoreEventHandling<'a> {
//    pub path: String,
//    pub parsed_pki_data: Arc<Mutex<ParsedPkiData<'a>>>,
//    pub parser: PkiParser,
//}
//
//pub trait FileEventExt {
//    fn get_paths(&self) -> &Vec<PathBuf>;
//
//    fn get_attrs(&self) -> &EventAttributes;
//
//    fn get_kind(&self) -> &EventKind;
//}
//
//impl FileEventExt for Event {
//    fn get_paths(&self) -> &Vec<PathBuf> {
//        &self.paths
//    }
//
//    fn get_attrs(&self) -> &EventAttributes {
//        &self.attrs
//    }
//
//    fn get_kind(&self) -> &EventKind {
//        &self.kind
//    }
//}
//
//impl<E> PkiWatcherEventHandler<E> for DefaultPkiFileStoreEventHandling<'_> where E: FileEventExt {
//    fn handle_event(&mut self, event: E) {
//        let kind = event.get_kind();
//        let path =  event.get_paths();
//        let attrs = event.get_attrs();
//
//        futures::executor::block_on(async move |kind, path, attrs| {
//            match kind {
//                EventKind::Any => {}
//                EventKind::Access(_) => {}
//                EventKind::Create(_) => {}
//                EventKind::Modify(modification) => match modification {
//                    ModifyKind::Any => {}
//
//                    ModifyKind::Data(_) => {
//                        let reader = tokio::fs::read(path).await.unwrap();
//                        let is_cleared_on_update = false;
//                        let cursor = Cursor::new(reader);
//                        let mut temp_parsed_pki_data = self.parsed_pki_data.deref().lock().await;
//                        if !is_cleared_on_update {
//                            self.parser
//                                .parse_pem(temp_parsed_pki_data.borrow_mut(), cursor)
//                                .unwrap();
//                        }
//                    }
//
//                    ModifyKind::Metadata(_) => {}
//                    ModifyKind::Name(_) => {}
//                    ModifyKind::Other => {}
//                },
//                EventKind::Remove(_) => {}
//                EventKind::Other => {}
//            }
//        })
//    }
//}
//
//impl EventHandler for DefaultPkiFileStoreEventHandling<'static> {
//    fn handle_event(&mut self, event: notify::Result<Event>) {
//        use PkiWatcherEventHandler;
//        let event = event.unwrap();
//        PkiWatcherEventHandler::handle_event(self, event);
//    }
//}
