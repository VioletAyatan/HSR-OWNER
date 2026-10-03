use super::*;
use std::net::Shutdown;

static CONNECTION_TEST: Mutex<()> = Mutex::new(());

fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (server, peer)
}

fn assert_command_budget_released() {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let permits: Vec<_> = (0..COMMAND_THREAD_LIMIT)
            .filter_map(|_| COMMAND_BUDGET.try_acquire())
            .collect();
        if permits.len() == COMMAND_THREAD_LIMIT {
            assert!(COMMAND_BUDGET.try_acquire().is_none());
            return;
        }
        drop(permits);
        assert!(
            Instant::now() < deadline,
            "command permits were not released"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn sender_is_disconnected(sender: &SyncSender<ServerFrame>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if matches!(
            sender.try_send(ServerFrame::Reply {
                id: 0,
                event: BackendEvent::DumperStatus { enabled: false }
            }),
            Err(mpsc::TrySendError::Disconnected(_))
        ) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

struct FaultSpawner {
    role: &'static str,
    panic: bool,
    contexts: Arc<Mutex<Vec<SpawnContext>>>,
}

impl ThreadSpawner for FaultSpawner {
    fn spawn(
        &self,
        context: SpawnContext,
        job: lifecycle::ThreadJob,
    ) -> std::io::Result<thread::JoinHandle<()>> {
        self.contexts.lock().unwrap().push(context);
        if context.role == self.role {
            if self.panic {
                panic!("injected spawn panic");
            }
            return Err(std::io::Error::other("injected spawn failure"));
        }
        NativeThreads.spawn(context, job)
    }
}

#[test]
fn writer_spawn_error_deregisters_client_without_panicking() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (server, _peer) = socket_pair();
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let spawner = FaultSpawner {
        role: "writer",
        panic: false,
        contexts: contexts.clone(),
    };
    let before: Vec<_> = CLIENTS.lock().unwrap().keys().copied().collect();
    let outcome = std::panic::catch_unwind(|| handle_connection_with_spawner(server, &spawner));
    let leaked: Vec<_> = CLIENTS
        .lock()
        .unwrap()
        .keys()
        .copied()
        .filter(|id| !before.contains(id))
        .collect();
    for id in &leaked {
        unregister_client(*id);
    }
    assert!(
        leaked.is_empty(),
        "failed writer setup leaked registrations {leaked:?}"
    );
    assert!(
        outcome.is_ok(),
        "spawn io::Error must not unwind the connection"
    );
    let contexts = contexts.lock().unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].role, "writer");
    assert!(contexts[0].client_id.is_some());
    assert!(contexts[0].peer.is_some());
    assert_eq!(contexts[0].request_id, None);
}

#[test]
fn command_spawn_error_replies_failed_for_the_same_request_without_started() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (server, mut peer) = socket_pair();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let recorded = contexts.clone();
    let worker = thread::spawn(move || {
        let spawner = FaultSpawner {
            role: "command",
            panic: false,
            contexts,
        };
        std::panic::catch_unwind(|| handle_connection_with_spawner(server, &spawner))
    });
    hsr_ipc::write_json_frame(
        &mut peer,
        &ClientFrame::Command {
            id: 2002,
            command: FrontendCommand::Dumper(DumperCommand::Run {
                action: DumperAction::Resources,
            }),
        },
    )
    .unwrap();
    let reply = hsr_ipc::read_json_frame::<_, ServerFrame>(&mut peer);
    let _ = peer.shutdown(Shutdown::Both);
    let outcome = worker.join().unwrap();
    assert_command_budget_released();
    assert!(
        matches!(reply, Ok(ServerFrame::Reply { id: 2002, event: BackendEvent::DumperFailed { action: DumperAction::Resources, ref error } }) if error.contains("spawn")),
        "expected only request-owned Failed, got {reply:?}"
    );
    assert!(
        outcome.is_ok(),
        "command spawn io::Error must not unwind the connection"
    );
    let recorded = recorded.lock().unwrap();
    let command_context = recorded
        .iter()
        .find(|context| context.role == "command")
        .unwrap();
    assert_eq!(command_context.request_id, Some(2002));
    assert!(command_context.client_id.is_some());
    assert!(command_context.peer.is_some());
}

struct HoldingCommands {
    gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
    entered: mpsc::Sender<SpawnContext>,
    finished: mpsc::Sender<()>,
}

impl ThreadSpawner for HoldingCommands {
    fn spawn(
        &self,
        context: SpawnContext,
        job: lifecycle::ThreadJob,
    ) -> std::io::Result<thread::JoinHandle<()>> {
        if context.role != "command" {
            return NativeThreads.spawn(context, job);
        }
        let gate = self.gate.clone();
        let entered = self.entered.clone();
        let finished = self.finished.clone();
        NativeThreads.spawn(
            context,
            Box::new(move || {
                entered.send(context).unwrap();
                let (lock, wake) = &*gate;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = wake.wait(released).unwrap();
                }
                drop(released);
                // Never run the unfixed path's extra Dumper request against game state.
                if context.request_id != Some(10099) {
                    job();
                }
                finished.send(()).unwrap();
            }),
        )
    }
}

#[test]
fn command_admission_is_bounded_before_spawning_and_rejects_dumper() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (server, mut peer) = socket_pair();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let held = gate.clone();
    let (entered, entered_rx) = mpsc::channel();
    let (finished, finished_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        handle_connection_with_spawner(
            server,
            &HoldingCommands {
                gate: held,
                entered,
                finished,
            },
        )
    });
    for id in 1..=16 {
        hsr_ipc::write_json_frame(
            &mut peer,
            &ClientFrame::Command {
                id,
                command: FrontendCommand::SetDumperEnabled { enabled: false },
            },
        )
        .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    hsr_ipc::write_json_frame(
        &mut peer,
        &ClientFrame::Command {
            id: 10098,
            command: FrontendCommand::StopSniffer,
        },
    )
    .unwrap();
    hsr_ipc::write_json_frame(
        &mut peer,
        &ClientFrame::Command {
            id: 10099,
            command: FrontendCommand::RunDumper {
                action: DumperAction::Resources,
            },
        },
    )
    .unwrap();
    let reply = hsr_ipc::read_json_frame::<_, ServerFrame>(&mut peer);
    let extra_spawn = entered_rx.try_recv();
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    let _ = peer.shutdown(Shutdown::Both);
    worker.join().unwrap();
    for _ in 0..16 {
        finished_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }
    assert_command_budget_released();
    assert!(
        matches!(reply, Ok(ServerFrame::Reply { id: 10099, event: BackendEvent::DumperFailed { action: DumperAction::Resources, ref error } }) if error.contains("limit")),
        "admission must produce Failed without spawning: {reply:?}"
    );
    assert!(
        extra_spawn.is_err(),
        "extra command spawned before admission: {extra_spawn:?}"
    );
}

#[test]
fn command_spawn_panic_cancels_writer_even_while_a_task_holds_sender() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (server, mut peer) = socket_pair();
    let before: Vec<_> = CLIENTS.lock().unwrap().keys().copied().collect();
    let (done, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let spawner = FaultSpawner {
            role: "command",
            panic: true,
            contexts: Arc::new(Mutex::new(Vec::new())),
        };
        let result = std::panic::catch_unwind(|| handle_connection_with_spawner(server, &spawner));
        done.send(result.is_err()).unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    let held = loop {
        let clients = CLIENTS.lock().unwrap();
        if let Some((id, sender)) = clients.iter().find(|(id, _)| !before.contains(id)) {
            break (*id, sender.clone());
        }
        drop(clients);
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    };
    hsr_ipc::write_json_frame(
        &mut peer,
        &ClientFrame::Command {
            id: 9,
            command: FrontendCommand::SetDumperEnabled { enabled: false },
        },
    )
    .unwrap();
    assert!(done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
    let deadline = Instant::now() + Duration::from_secs(1);
    let disconnected = loop {
        if matches!(
            held.1.try_send(ServerFrame::Reply {
                id: 9,
                event: BackendEvent::DumperStatus { enabled: false }
            }),
            Err(mpsc::TrySendError::Disconnected(_))
        ) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let _ = peer.shutdown(Shutdown::Both);
    drop(held.1);
    worker.join().unwrap();
    assert!(!CLIENTS.lock().unwrap().contains_key(&held.0));
    assert_command_budget_released();
    assert!(
        disconnected,
        "unwind left a detached writer accepting task output"
    );
}

struct FailFirstConnection {
    attempts: std::sync::atomic::AtomicUsize,
    completed: mpsc::Sender<()>,
}

impl ThreadSpawner for FailFirstConnection {
    fn spawn(
        &self,
        context: SpawnContext,
        job: lifecycle::ThreadJob,
    ) -> std::io::Result<thread::JoinHandle<()>> {
        assert_eq!(context.role, "connection");
        assert!(context.peer.is_some());
        assert!(context.client_id.is_none());
        if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(std::io::Error::other("injected connection spawn failure"))
        } else {
            let completed = self.completed.clone();
            NativeThreads.spawn(
                context,
                Box::new(move || {
                    job();
                    completed.send(()).unwrap();
                }),
            )
        }
    }
}

#[test]
fn connection_spawn_error_does_not_stop_the_accept_loop() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (first, mut first_peer) = socket_pair();
    let (second, second_peer) = socket_pair();
    second_peer.shutdown(Shutdown::Both).unwrap();
    first_peer
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let (completed, completed_rx) = mpsc::channel();
    let spawner = FailFirstConnection {
        attempts: std::sync::atomic::AtomicUsize::new(0),
        completed,
    };
    let outcome = std::panic::catch_unwind(|| serve_incoming([Ok(first), Ok(second)], &spawner));
    let mut byte = [0];
    let closed = std::io::Read::read(&mut first_peer, &mut byte);
    assert!(
        outcome.is_ok(),
        "connection spawn failure killed the production accept loop"
    );
    assert_eq!(
        spawner.attempts.load(Ordering::SeqCst),
        2,
        "next accepted connection was skipped"
    );
    completed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(
        matches!(closed, Ok(0)),
        "failed connection socket was not closed: {closed:?}"
    );
}

struct CapturedLogs(Mutex<VecDeque<String>>);
static CAPTURED_LOGS: CapturedLogs = CapturedLogs(Mutex::new(VecDeque::new()));

impl log::Log for CapturedLogs {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        let mut logs = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if logs.len() == 4096 {
            logs.pop_front();
        }
        logs.push_back(record.args().to_string());
    }
    fn flush(&self) {}
}

fn capture_logs() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        log::set_logger(&CAPTURED_LOGS).unwrap();
        log::set_max_level(log::LevelFilter::Debug);
    });
}

#[test]
fn dumper_diagnostics_identify_gate_owner_client_and_request() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    capture_logs();
    let (out, rx) = mpsc::sync_channel(8);
    let client_id = register_client(out.clone());
    let responder = Responder {
        id: 424242,
        client_id,
        out,
    };
    let gate = task_gate::TaskGate::new();
    run_dumper(&responder, DumperAction::Resources, &gate, || Ok(()));
    unregister_client(client_id);
    assert!(matches!(
        rx.recv().unwrap(),
        ServerFrame::Reply {
            id: 424242,
            event: BackendEvent::DumperStarted { .. }
        }
    ));
    assert!(matches!(
        rx.recv().unwrap(),
        ServerFrame::Reply {
            id: 424242,
            event: BackendEvent::DumperFinished { .. }
        }
    ));
    let logs = CAPTURED_LOGS.0.lock().unwrap();
    assert!(
        logs.iter().any(|line| line.contains("ownership=acquired")
            && line.contains(&format!("client_id={client_id}"))
            && line.contains("request_id=424242")
            && line.contains("Resources")),
        "Dumper gate ownership was not attributed: {logs:?}"
    );
}

#[test]
fn writer_diagnostics_report_entry_and_only_the_first_write() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    capture_logs();
    let (server, mut peer) = socket_pair();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let recorded = contexts.clone();
    let worker = thread::spawn(move || {
        handle_connection_with_spawner(
            server,
            &FaultSpawner {
                role: "none",
                panic: false,
                contexts,
            },
        )
    });
    for id in 91001..=91003 {
        hsr_ipc::write_json_frame(
            &mut peer,
            &ClientFrame::Command {
                id,
                command: FrontendCommand::SetDumperEnabled { enabled: false },
            },
        )
        .unwrap();
        let reply: ServerFrame = hsr_ipc::read_json_frame(&mut peer).unwrap();
        assert!(
            matches!(reply, ServerFrame::Reply { id: reply_id, event: BackendEvent::DumperStatus { enabled: false } } if reply_id == id)
        );
    }
    peer.shutdown(Shutdown::Both).unwrap();
    worker.join().unwrap();
    let context = *recorded
        .lock()
        .unwrap()
        .iter()
        .find(|context| context.role == "writer")
        .unwrap();
    let client = format!("client_id={}", context.client_id.unwrap());
    let logs = CAPTURED_LOGS.0.lock().unwrap();
    let owned: Vec<_> = logs.iter().filter(|line| line.contains(&client)).collect();
    assert!(
        owned.iter().any(|line| line.contains("writer entry")
            && line.contains("writer_tid=")
            && line.contains("peer=")),
        "writer entry context missing: {owned:?}"
    );
    assert_eq!(
        owned
            .iter()
            .filter(|line| line.contains("first_write_begin"))
            .count(),
        1,
        "per-frame writer diagnostics are not bounded: {owned:?}"
    );
    assert!(
        owned
            .iter()
            .any(|line| line.contains("first_write_complete")
                && line.contains("request_id=Some(91001)")),
        "first reply write completion missing: {owned:?}"
    );
}

#[test]
fn writer_write_error_closes_reader_and_reports_request_context() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    capture_logs();
    let (server, mut peer) = socket_pair();
    let control = server.try_clone().unwrap();
    control.shutdown(Shutdown::Write).unwrap();
    let before: Vec<_> = CLIENTS.lock().unwrap().keys().copied().collect();
    let (done, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        handle_connection(server);
        done.send(()).unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    let held = loop {
        let clients = CLIENTS.lock().unwrap();
        if let Some((id, sender)) = clients.iter().find(|(id, _)| !before.contains(id)) {
            break (*id, sender.clone());
        }
        drop(clients);
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    };
    hsr_ipc::write_json_frame(
        &mut peer,
        &ClientFrame::Command {
            id: 91919,
            command: FrontendCommand::SetDumperEnabled { enabled: false },
        },
    )
    .unwrap();
    let stopped = done_rx.recv_timeout(Duration::from_secs(1));
    let _ = control.shutdown(Shutdown::Both);
    worker.join().unwrap();
    assert!(
        stopped.is_ok(),
        "writer failure did not wake reader: {stopped:?}"
    );
    assert!(!CLIENTS.lock().unwrap().contains_key(&held.0));
    let logs = CAPTURED_LOGS.0.lock().unwrap();
    assert!(
        logs.iter().any(|line| line.contains("writer write_failed")
            && line.contains(&format!("client_id={}", held.0))
            && line.contains("request_id=Some(91919)")
            && line.contains("peer=")
            && line.contains("writer_tid=")),
        "write failure context missing: {logs:?}"
    );
}

#[test]
fn idle_and_fragmented_command_survive_read_poll_timeouts() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (server, mut peer) = socket_pair();
    server
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let worker = thread::spawn(move || handle_connection(server));
    let frame = ClientFrame::Command {
        id: 92929,
        command: FrontendCommand::SetDumperEnabled { enabled: false },
    };
    let mut bytes = Vec::new();
    hsr_ipc::write_json_frame(&mut bytes, &frame).unwrap();
    let mut sent = Ok(());
    let split = 4 + (bytes.len() - 4) / 2;
    for chunk in [&bytes[..2], &bytes[2..4], &bytes[4..split], &bytes[split..]] {
        thread::sleep(Duration::from_millis(150));
        sent = std::io::Write::write_all(&mut peer, chunk);
        if sent.is_err() {
            break;
        }
    }
    let reply = if sent.is_ok() {
        hsr_ipc::read_json_frame::<_, ServerFrame>(&mut peer)
    } else {
        Err(anyhow::anyhow!("fragment send failed: {sent:?}"))
    };
    let _ = peer.shutdown(Shutdown::Both);
    worker.join().unwrap();
    assert!(
        matches!(
            reply,
            Ok(ServerFrame::Reply {
                id: 92929,
                event: BackendEvent::DumperStatus { enabled: false }
            })
        ),
        "read polling discarded idle/partial frame: {reply:?}"
    );
}

#[test]
fn spawn_failure_diagnostics_include_role_owner_peer_and_caller_tid() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    capture_logs();
    let (server, _peer) = socket_pair();
    let contexts = Arc::new(Mutex::new(Vec::new()));
    handle_connection_with_spawner(
        server,
        &FaultSpawner {
            role: "writer",
            panic: false,
            contexts: contexts.clone(),
        },
    );
    let context = contexts.lock().unwrap()[0];
    let client = format!("client_id=Some({})", context.client_id.unwrap());
    let logs = CAPTURED_LOGS.0.lock().unwrap();
    assert!(
        logs.iter().any(|line| line.contains("spawn role=writer")
            && line.contains(&client)
            && line.contains("request_id=None")
            && line.contains("peer=Some(")
            && line.contains("caller_tid=")
            && line.contains("spawn_result=error")
            && line.contains("injected spawn failure")),
        "spawn failure diagnostics missing: {logs:?}"
    );
}

#[test]
fn background_spawn_failure_is_logged_and_drops_job_without_unwinding() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    capture_logs();
    for role in ["server", "packet-stream", "log-stream"] {
        let contexts = Arc::new(Mutex::new(Vec::new()));
        let spawner = FaultSpawner {
            role,
            panic: false,
            contexts: contexts.clone(),
        };
        let (owned, owned_rx) = mpsc::channel::<()>();
        let result = std::panic::catch_unwind(|| {
            start_background(
                &spawner,
                role,
                Box::new(move || {
                    drop(owned);
                    panic!("must not run failed background job")
                }),
            )
        });
        assert!(matches!(
            owned_rx.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
        assert!(
            result.is_ok(),
            "background role {role} unwound on spawn failure"
        );
        let context = contexts.lock().unwrap()[0];
        assert!(
            context.client_id.is_none() && context.request_id.is_none() && context.peer.is_none()
        );
        let logs = CAPTURED_LOGS.0.lock().unwrap();
        assert!(
            logs.iter()
                .any(|line| line.contains(&format!("spawn role={role}"))
                    && line.contains("spawn_result=error"))
        );
    }
}

struct NotifyOnDrop(mpsc::Sender<()>);

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

struct PanicJobSpawner {
    role: &'static str,
    entered: mpsc::Sender<SpawnContext>,
    completed: mpsc::Sender<()>,
}

impl ThreadSpawner for PanicJobSpawner {
    fn spawn(
        &self,
        context: SpawnContext,
        job: lifecycle::ThreadJob,
    ) -> std::io::Result<thread::JoinHandle<()>> {
        if context.role != self.role {
            return NativeThreads.spawn(context, job);
        }
        let entered = self.entered.clone();
        let completed = self.completed.clone();
        NativeThreads.spawn(
            context,
            Box::new(move || {
                let _completion = NotifyOnDrop(completed);
                let _job = job;
                entered.send(context).unwrap();
                panic!("injected worker panic");
            }),
        )
    }
}

#[test]
fn writer_worker_panic_deregisters_client_and_cancels_reader() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (server, mut peer) = socket_pair();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let (entered, entered_rx) = mpsc::channel();
    let (completed, completed_rx) = mpsc::channel();
    let (done, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        handle_connection_with_spawner(
            server,
            &PanicJobSpawner {
                role: "writer",
                entered,
                completed,
            },
        );
        done.send(()).unwrap();
    });
    let context = entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    completed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    worker.join().unwrap();
    assert!(
        !CLIENTS
            .lock()
            .unwrap()
            .contains_key(&context.client_id.unwrap())
    );
    let mut byte = [0];
    assert!(matches!(std::io::Read::read(&mut peer, &mut byte), Ok(0)));
}

#[test]
fn command_worker_panic_releases_admission_permit() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (server, mut peer) = socket_pair();
    let (entered, entered_rx) = mpsc::channel();
    let (completed, completed_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        handle_connection_with_spawner(
            server,
            &PanicJobSpawner {
                role: "command",
                entered,
                completed,
            },
        )
    });
    hsr_ipc::write_json_frame(
        &mut peer,
        &ClientFrame::Command {
            id: 94001,
            command: FrontendCommand::SetDumperEnabled { enabled: false },
        },
    )
    .unwrap();
    let context = entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(context.request_id, Some(94001));
    completed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_command_budget_released();
    peer.shutdown(Shutdown::Both).unwrap();
    worker.join().unwrap();
}

#[test]
fn writer_spawn_panic_deregisters_exact_client() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (server, mut peer) = socket_pair();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let (other_out, _other_rx) = mpsc::sync_channel(1);
    let other_id = register_client(other_out);
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let spawner = FaultSpawner {
        role: "writer",
        panic: true,
        contexts: contexts.clone(),
    };
    let result = std::panic::catch_unwind(|| handle_connection_with_spawner(server, &spawner));
    let context = contexts.lock().unwrap()[0];
    let clients = CLIENTS.lock().unwrap();
    let own_removed = !clients.contains_key(&context.client_id.unwrap());
    let other_preserved = clients.contains_key(&other_id);
    drop(clients);
    unregister_client(other_id);
    assert!(result.is_err());
    assert!(
        own_removed && other_preserved,
        "registration cleanup removed the wrong client"
    );
    let mut byte = [0];
    assert!(matches!(std::io::Read::read(&mut peer, &mut byte), Ok(0)));
}

#[test]
fn spawn_rejection_preserves_all_dumper_actions_and_does_not_fake_other_failures() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (server, mut peer) = socket_pair();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let worker = thread::spawn(move || {
        handle_connection_with_spawner(
            server,
            &FaultSpawner {
                role: "command",
                panic: false,
                contexts: Arc::new(Mutex::new(Vec::new())),
            },
        )
    });
    hsr_ipc::write_json_frame(
        &mut peer,
        &ClientFrame::Command {
            id: 94949,
            command: FrontendCommand::StopSniffer,
        },
    )
    .unwrap();
    let actions = DumperAction::ALL.into_iter().chain(
        hsr_ipc::ProtoDumpMode::ALL
            .into_iter()
            .map(|mode| DumperAction::Proto { mode }),
    );
    for (index, action) in actions.enumerate() {
        for (offset, command) in [
            FrontendCommand::RunDumper { action },
            FrontendCommand::Dumper(DumperCommand::Run { action }),
        ]
        .into_iter()
        .enumerate()
        {
            let id = 95000 + (index * 2 + offset) as u64;
            hsr_ipc::write_json_frame(&mut peer, &ClientFrame::Command { id, command }).unwrap();
            let reply: ServerFrame = hsr_ipc::read_json_frame(&mut peer).unwrap();
            assert!(
                matches!(reply, ServerFrame::Reply { id: actual_id, event: BackendEvent::DumperFailed { action: actual_action, .. } } if actual_id == id && actual_action == action),
                "unexpected Started/Finished/non-Dumper failure: {reply:?}"
            );
        }
    }
    peer.set_read_timeout(Some(Duration::from_millis(30)))
        .unwrap();
    let extra = hsr_ipc::read_json_frame::<_, ServerFrame>(&mut peer);
    let _ = peer.shutdown(Shutdown::Both);
    worker.join().unwrap();
    assert!(
        extra.is_err(),
        "rejection produced extra terminal frames: {extra:?}"
    );
    assert_command_budget_released();
}

#[test]
fn native_command_thread_is_named_and_success_is_not_logged_per_command() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    capture_logs();
    spawn_thread(
        &NativeThreads,
        SpawnContext {
            role: "command",
            client_id: Some(123456789),
            request_id: Some(94002),
            peer: None,
        },
        Box::new(|| {
            assert_eq!(
                thread::current().name(),
                Some("ipc-command-c123456789-r94002")
            );
        }),
    )
    .unwrap()
    .join()
    .unwrap();
    let logs = CAPTURED_LOGS.0.lock().unwrap();
    assert!(!logs.iter().any(|line| line.contains("spawn role=command")
        && line.contains("client_id=Some(123456789)")
        && line.contains("spawn_result=ok")));
}

#[test]
fn eof_does_not_join_active_dumper_or_release_its_gate_before_task_completion() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (server, mut peer) = socket_pair();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let before: Vec<_> = CLIENTS.lock().unwrap().keys().copied().collect();
    let (done, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        handle_connection(server);
        done.send(()).unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    let (client_id, out) = loop {
        let clients = CLIENTS.lock().unwrap();
        if let Some((id, sender)) = clients.iter().find(|(id, _)| !before.contains(id)) {
            break (*id, sender.clone());
        }
        drop(clients);
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    };
    let responder = Responder {
        id: 96001,
        client_id,
        out: out.clone(),
    };
    let gate = Arc::new(task_gate::TaskGate::new());
    let active_gate = gate.clone();
    let (release, release_rx) = mpsc::channel();
    let dumper = thread::spawn(move || {
        run_dumper(&responder, DumperAction::Resources, &active_gate, || {
            release_rx.recv().unwrap();
            Ok(())
        })
    });
    let started: ServerFrame = hsr_ipc::read_json_frame(&mut peer).unwrap();
    assert!(matches!(
        started,
        ServerFrame::Reply {
            id: 96001,
            event: BackendEvent::DumperStarted { .. }
        }
    ));
    peer.shutdown(Shutdown::Write).unwrap();
    let stopped = done_rx.recv_timeout(Duration::from_secs(1));
    let gate_held = gate.try_enter().is_none();
    let writer_stopped = sender_is_disconnected(&out);
    release.send(()).unwrap();
    dumper.join().unwrap();
    worker.join().unwrap();
    assert!(
        stopped.is_ok(),
        "EOF waited for an active Dumper task: {stopped:?}"
    );
    assert!(
        gate_held,
        "connection cancellation released a still-running Dumper gate"
    );
    assert!(
        writer_stopped,
        "disconnected writer retained the task sender"
    );
    assert!(
        gate.try_enter().is_some(),
        "terminal send after disconnect retained the Dumper gate"
    );
}

#[test]
fn eof_with_held_responder_sender_does_not_keep_connection_worker_alive() {
    let _serial = CONNECTION_TEST.lock().unwrap();
    let (server, peer) = socket_pair();
    let before: Vec<_> = CLIENTS.lock().unwrap().keys().copied().collect();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        handle_connection(server);
        done_tx.send(()).unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    let held_sender = loop {
        let clients = CLIENTS.lock().unwrap();
        if let Some((_, sender)) = clients.iter().find(|(id, _)| !before.contains(id)) {
            break sender.clone();
        }
        drop(clients);
        assert!(Instant::now() < deadline, "connection was not registered");
        thread::sleep(Duration::from_millis(5));
    };
    peer.shutdown(Shutdown::Both).unwrap();
    let stopped = done_rx.recv_timeout(Duration::from_secs(1));
    // Clean up the baseline's stuck writer before reporting the regression.
    let writer_stopped = sender_is_disconnected(&held_sender);
    drop(held_sender);
    worker.join().unwrap();
    assert!(
        stopped.is_ok(),
        "EOF must cancel the writer even while a task holds its sender: {stopped:?}"
    );
    assert!(
        writer_stopped,
        "EOF left the writer receiver alive while a task held its sender"
    );
}
