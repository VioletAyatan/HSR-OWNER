use gpui::{prelude::FluentBuilder as _, *};
use gpui_component::{
    ActiveTheme, Disableable as _, Sizable as _,
    button::{Button, ButtonVariants as _},
    h_flex, v_flex,
};
use hsr_ipc::{BackendEvent, DumperAction, ProtoDumpMode};

pub struct DumperPage {
    proto_mode: ProtoDumpMode,
    status: Option<String>,
    active: Option<DumperAction>,
}

impl DumperPage {
    pub fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        crate::ui::spawn_event_bridge(cx, |this, event, _cx| match event {
            BackendEvent::DumperStarted { action } => {
                this.active = Some(*action);
                this.status = Some(format!("Running {}…", action.label()));
            }
            BackendEvent::DumperFinished { action, seconds } => {
                this.active = None;
                this.status = Some(format!("{} finished in {seconds}s", action.label()));
            }
            BackendEvent::DumperFailed { action, error } => {
                this.active = None;
                this.status = Some(format!("{} failed: {error}", action.label()));
            }
            _ => {}
        });

        cx.spawn(async move |this, cx| {
            loop {
                smol::Timer::after(std::time::Duration::from_millis(250)).await;
                if this.update(cx, |this, cx| {
                    if this.active.is_some() && !crate::ipc::is_connected() {
                        this.active = None;
                        this.status = Some("Connection lost; backend dump may still be running. Check hsr-owner.log.".into());
                        cx.notify();
                    }
                }).is_err() { break; }
            }
        }).detach();

        Self {
            proto_mode: ProtoDumpMode::WriteTo,
            status: None,
            active: None,
        }
    }

    fn action_card(&self, action: DumperAction, cx: &mut Context<Self>) -> AnyElement {
        let is_proto = matches!(action, DumperAction::Proto { .. });
        let muted = cx.theme().muted_foreground;
        let dump_id = SharedString::from(format!("dump-{}", action.label()));

        crate::ui::card(cx)
            .child(
                h_flex()
                    .justify_between()
                    .items_start()
                    .gap_4()
                    .child(
                        v_flex()
                            .gap_1()
                            .child(
                                div()
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(cx.theme().foreground)
                                    .child(action.label()),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(muted)
                                    .child(action.description()),
                            ),
                    )
                    .child(
                        Button::new(dump_id)
                            .custom(crate::components::ui::gold_button_variant(cx))
                            .label("Dump")
                            .disabled(self.active.is_some())
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if this.active.is_some() {
                                    return;
                                }
                                let action = if matches!(action, DumperAction::Proto { .. }) {
                                    DumperAction::Proto {
                                        mode: this.proto_mode,
                                    }
                                } else {
                                    action
                                };
                                this.active = Some(action);
                                this.status = Some(format!("Starting {}…", action.label()));
                                cx.spawn(async move |this, cx| {
                                    let result = cx
                                        .background_executor()
                                        .spawn(async move { crate::ipc::send_dumper(action) })
                                        .await;
                                    if let Err(error) = result {
                                        let _ = this.update(cx, |this, cx| {
                                            if this.active == Some(action) {
                                                this.active = None;
                                                this.status = Some(format!(
                                                    "{} could not start: {error:#}",
                                                    action.label()
                                                ));
                                                cx.notify();
                                            }
                                        });
                                    }
                                })
                                .detach();
                                cx.notify();
                            })),
                    ),
            )
            .when(is_proto, |card| card.child(self.proto_modes(cx)))
            .into_any_element()
    }

    fn proto_modes(&self, cx: &mut Context<Self>) -> AnyElement {
        h_flex()
            .gap_2()
            .flex_wrap()
            .children(ProtoDumpMode::ALL.iter().map(|&mode| {
                let selected = self.proto_mode == mode;
                let button = Button::new(SharedString::from(mode.id()))
                    .label(mode.label())
                    .small();
                let button = if selected {
                    button.custom(crate::components::ui::gold_button_variant(cx))
                } else {
                    button.ghost()
                };
                button.on_click(cx.listener(move |this, _, _, cx| {
                    this.proto_mode = mode;
                    cx.notify();
                }))
            }))
            .into_any_element()
    }
}

impl Render for DumperPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let cards = DumperAction::ALL
            .iter()
            .map(|&action| self.action_card(action, cx))
            .collect::<Vec<_>>();

        v_flex()
            .size_full()
            .p_4()
            .gap_3()
            .child(crate::ui::page_header(
                "Dumper",
                "Dump game metadata, protobufs, scripts & resources",
                cx,
            ))
            .when_some(self.status.clone(), |this, status| {
                this.child(div().text_sm().text_color(muted).child(status))
            })
            .child(
                div()
                    .id("dumper-scroll")
                    .flex_1()
                    .overflow_y_scroll()
                    .child(v_flex().gap_3().children(cards)),
            )
    }
}
