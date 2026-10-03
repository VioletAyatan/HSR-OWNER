use std::{
    io::{self, Read},
    net::{Shutdown, SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(super) struct ConnectionState {
    client_id: u64,
    pub alive: AtomicBool,
    pub socket: TcpStream,
}

impl ConnectionState {
    pub fn new(client_id: u64, socket: TcpStream) -> Self {
        Self {
            client_id,
            alive: AtomicBool::new(true),
            socket,
        }
    }

    pub fn close(&self) {
        if self.alive.swap(false, Ordering::SeqCst) {
            super::unregister_client(self.client_id);
            let _ = self.socket.shutdown(Shutdown::Both);
        }
    }
}

/// Both reader and writer close the shared connection on return or unwind.
pub(super) struct ConnectionLifetime(pub Arc<ConnectionState>);

impl Drop for ConnectionLifetime {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Retry timeouts inside Read, so read_exact retains partial headers/payloads.
/// Socket shutdown alone need not interrupt a pending read on a cloned socket.
pub(super) struct ConnectionReader<'a>(pub &'a ConnectionState);

impl Read for ConnectionReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.0.alive.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "IPC connection cancelled",
                ));
            }
            match (&self.0.socket).read(buffer) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}

/// This is a thread budget, not a bound on game metadata or handler work.
pub(super) struct CommandBudget {
    limit: usize,
    active: AtomicUsize,
}

impl CommandBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            active: AtomicUsize::new(0),
        }
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<CommandPermit> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.limit {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(CommandPermit(self.clone())),
                Err(observed) => active = observed,
            }
        }
    }
}

pub(super) struct CommandPermit(Arc<CommandBudget>);

impl Drop for CommandPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) type ThreadJob = Box<dyn FnOnce() + Send + 'static>;

#[derive(Clone, Copy, Debug)]
pub(super) struct SpawnContext {
    pub role: &'static str,
    pub client_id: Option<u64>,
    pub request_id: Option<u64>,
    pub peer: Option<SocketAddr>,
}

pub(super) trait ThreadSpawner {
    /// An error must drop the job rather than schedule it for later execution.
    fn spawn(&self, context: SpawnContext, job: ThreadJob) -> io::Result<JoinHandle<()>>;
}

pub(super) struct NativeThreads;

impl ThreadSpawner for NativeThreads {
    fn spawn(&self, context: SpawnContext, job: ThreadJob) -> io::Result<JoinHandle<()>> {
        let mut name = format!("ipc-{}", context.role);
        if let Some(client_id) = context.client_id {
            name.push_str(&format!("-c{client_id}"));
        }
        if let Some(request_id) = context.request_id {
            name.push_str(&format!("-r{request_id}"));
        }
        thread::Builder::new().name(name).spawn(job)
    }
}

pub(super) fn spawn_thread(
    spawner: &impl ThreadSpawner,
    context: SpawnContext,
    job: ThreadJob,
) -> io::Result<JoinHandle<()>> {
    let caller_tid = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
    let result = spawner.spawn(context, job);
    match &result {
        Ok(_) if context.role != "command" => log::debug!(
            "[Tunnel] spawn role={} client_id={:?} request_id={:?} peer={:?} caller_tid={caller_tid} spawn_result=ok",
            context.role,
            context.client_id,
            context.request_id,
            context.peer
        ),
        Err(error) => log::warn!(
            "[Tunnel] spawn role={} client_id={:?} request_id={:?} peer={:?} caller_tid={caller_tid} spawn_result=error os_error={:?}: {error}",
            context.role,
            context.client_id,
            context.request_id,
            context.peer,
            error.raw_os_error()
        ),
        Ok(_) => {}
    }
    result
}
