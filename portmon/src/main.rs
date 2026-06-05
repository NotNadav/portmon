// PortMon: live GUI of every TCP/UDP socket and the process that owns it.

// Hide the console window in release builds (this is a GUI app).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod net;

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use net::{Conn, Resolver};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::os::windows::process::CommandExt;
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};

/// How long a new socket stays highlighted, in seconds.
const FLASH_SECS: f32 = 3.0;

/// Blend two colors: t=0 gives a, t=1 gives b.
fn lerp_color(a: egui::Color32, b: egui::Color32, t: f32) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    let m = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    egui::Color32::from_rgb(m(a.r(), b.r()), m(a.g(), b.g()), m(a.b(), b.b()))
}

/// Draw a cell. A flash color (new row) overrides the normal one; else theme.
fn cell(ui: &mut egui::Ui, text: &str, flash: Option<egui::Color32>, normal: Option<egui::Color32>) {
    match flash.or(normal) {
        Some(c) => {
            ui.colored_label(c, text);
        }
        None => {
            ui.label(text);
        }
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1040.0, 640.0])
            .with_min_inner_size([720.0, 380.0])
            .with_title("PortMon — live socket monitor"),
        ..Default::default()
    };
    eframe::run_native("PortMon", options, Box::new(|_cc| Ok(Box::new(App::new()))))
}

/// Column the table is sorted by.
#[derive(PartialEq, Clone, Copy)]
enum SortCol {
    Proto,
    Local,
    Remote,
    Service,
    State,
    Pid,
    Process,
}

struct App {
    sys: System,
    resolver: Resolver,
    seen: HashMap<String, Instant>, // socket key -> when first seen (for flash)
    rows: Vec<Conn>,
    filter: String,
    auto: bool,
    interval_secs: f32,
    last: Instant,
    sort: SortCol,
    asc: bool,
    show_tcp: bool,
    show_udp: bool,
    listening_only: bool,
}

impl App {
    fn new() -> Self {
        let mut sys = System::new();
        let rows = net::gather(&mut sys);
        // Backdate existing sockets so they don't all flash on startup.
        let now = Instant::now();
        let stamp = now
            .checked_sub(Duration::from_secs_f32(FLASH_SECS + 1.0))
            .unwrap_or(now);
        let seen = rows.iter().map(|c| (c.key.clone(), stamp)).collect();
        Self {
            sys,
            resolver: Resolver::new(),
            seen,
            rows,
            filter: String::new(),
            auto: true,
            interval_secs: 2.0,
            last: Instant::now(),
            sort: SortCol::Pid,
            asc: true,
            show_tcp: true,
            show_udp: true,
            listening_only: false,
        }
    }

    fn refresh(&mut self) {
        self.rows = net::gather(&mut self.sys);
        let now = Instant::now();
        // Drop sockets that closed; stamp new ones with now so they flash.
        let current: HashSet<&String> = self.rows.iter().map(|c| &c.key).collect();
        self.seen.retain(|k, _| current.contains(k));
        for c in &self.rows {
            self.seen.entry(c.key.clone()).or_insert(now);
        }
        self.last = now;
    }

    /// Kill a process, then refresh so its sockets drop off.
    fn kill_pid(&mut self, pid: u32) {
        if let Some(p) = self.sys.process(Pid::from_u32(pid)) {
            p.kill();
        }
        self.refresh();
    }

    /// Open Explorer with the process's exe selected.
    fn reveal_pid(&mut self, pid: u32) {
        if let Some(path) = self
            .sys
            .process(Pid::from_u32(pid))
            .and_then(|p| p.exe())
            .map(|p| p.to_path_buf())
        {
            // raw_arg keeps the /select,"path" syntax intact when the path has spaces.
            let _ = std::process::Command::new("explorer")
                .raw_arg(format!("/select,\"{}\"", path.display()))
                .spawn();
        }
    }

    /// Clickable column header; also toggles sort direction.
    fn header_btn(&mut self, ui: &mut egui::Ui, label: &str, col: SortCol) {
        let arrow = if self.sort == col {
            if self.asc { " ▲" } else { " ▼" }
        } else {
            ""
        };
        if ui.button(format!("{label}{arrow}")).clicked() {
            if self.sort == col {
                self.asc = !self.asc; // same column, flip direction
            } else {
                self.sort = col;
                self.asc = true;
            }
        }
    }

    /// Draw the table. kill/reveal collect right-click requests for the caller
    /// to run once the table is done borrowing.
    #[allow(clippy::too_many_arguments)]
    fn table(
        &mut self,
        ui: &mut egui::Ui,
        view: &[Conn],
        now: Instant,
        seen: &HashMap<String, Instant>,
        resolver: &Resolver,
        kill: &Cell<Option<u32>>,
        reveal: &Cell<Option<u32>>,
    ) {
        let gray = egui::Color32::from_rgb(190, 190, 190);
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(72.0)) // proto
            .column(Column::auto().at_least(165.0)) // local
            .column(Column::auto().at_least(175.0)) // remote
            .column(Column::auto().at_least(78.0)) // service
            .column(Column::auto().at_least(95.0)) // state
            .column(Column::auto().at_least(56.0)) // pid
            .column(Column::remainder().at_least(120.0)) // process
            .header(22.0, |mut h| {
                h.col(|ui| self.header_btn(ui, "Proto", SortCol::Proto));
                h.col(|ui| self.header_btn(ui, "Local", SortCol::Local));
                h.col(|ui| self.header_btn(ui, "Remote", SortCol::Remote));
                h.col(|ui| self.header_btn(ui, "Service", SortCol::Service));
                h.col(|ui| self.header_btn(ui, "State", SortCol::State));
                h.col(|ui| self.header_btn(ui, "PID", SortCol::Pid));
                h.col(|ui| self.header_btn(ui, "Process", SortCol::Process));
            })
            .body(|body| {
                body.rows(18.0, view.len(), |mut row| {
                    let c = &view[row.index()];

                    // New rows glow green, fading to the normal color over FLASH_SECS.
                    let age = now
                        .saturating_duration_since(*seen.get(&c.key).unwrap_or(&now))
                        .as_secs_f32();
                    let flash = (age < FLASH_SECS).then(|| {
                        lerp_color(
                            egui::Color32::from_rgb(90, 230, 140),
                            gray,
                            age / FLASH_SECS,
                        )
                    });

                    row.col(|ui| {
                        let proto_color = if c.proto.starts_with("TCP") {
                            egui::Color32::from_rgb(120, 170, 255)
                        } else {
                            egui::Color32::from_rgb(255, 180, 120)
                        };
                        cell(ui, &c.proto, flash, Some(proto_color));
                    });
                    row.col(|ui| cell(ui, &c.local, flash, None));
                    row.col(|ui| {
                        // Show the hostname if resolved, raw ip:port on hover.
                        let (text, hover) = match c.remote_ip.and_then(|ip| resolver.host(ip)) {
                            Some(host) => (format!("{host}:{}", c.remote_port), Some(&c.remote)),
                            None => (c.remote.clone(), None),
                        };
                        let resp = match flash {
                            Some(fc) => ui.colored_label(fc, &text),
                            None => ui.label(&text),
                        };
                        if let Some(h) = hover {
                            resp.on_hover_text(h);
                        }
                    });
                    row.col(|ui| cell(ui, &c.service, flash, Some(gray)));
                    row.col(|ui| {
                        let state_color = c.listening.then_some(egui::Color32::from_rgb(120, 220, 120));
                        cell(ui, &c.state, flash, state_color);
                    });
                    row.col(|ui| cell(ui, &c.pid.to_string(), flash, None));
                    row.col(|ui| cell(ui, &c.process, flash, None));

                    row.response().context_menu(|ui| {
                        ui.label(format!("PID {} · {}", c.pid, c.process));
                        ui.separator();
                        if ui
                            .add_enabled(c.pid != 0, egui::Button::new("⛔ End process"))
                            .clicked()
                        {
                            kill.set(Some(c.pid));
                            ui.close();
                        }
                        if ui
                            .add_enabled(c.pid != 0, egui::Button::new("📂 Open file location"))
                            .clicked()
                        {
                            reveal.set(Some(c.pid));
                            ui.close();
                        }
                        if ui.button("Copy local address").clicked() {
                            ui.ctx().copy_text(c.local.clone());
                            ui.close();
                        }
                        if c.remote != "—" && ui.button("Copy remote address").clicked() {
                            ui.ctx().copy_text(c.remote.clone());
                            ui.close();
                        }
                    });
                });
            });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.auto && self.last.elapsed() >= Duration::from_secs_f32(self.interval_secs) {
            self.refresh();
        }

        egui::Panel::top("toolbar").resizable(false).show_inside(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("⟳ Refresh").clicked() {
                    self.refresh();
                }
                ui.checkbox(&mut self.auto, "Auto");
                ui.add(
                    egui::Slider::new(&mut self.interval_secs, 0.5..=10.0)
                        .text("s")
                        .fixed_decimals(1),
                );
                ui.separator();
                ui.label("🔎");
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("filter…")
                        .desired_width(180.0),
                );
                if !self.filter.is_empty() && ui.button("✕").clicked() {
                    self.filter.clear();
                }
                ui.separator();
                ui.checkbox(&mut self.show_tcp, "TCP");
                ui.checkbox(&mut self.show_udp, "UDP");
                ui.checkbox(&mut self.listening_only, "Listening only");
            });
            ui.add_space(4.0);
        });

        // Clone the matched rows so the table can take &mut self while sorting.
        let f = self.filter.to_lowercase();
        let mut view: Vec<Conn> = self
            .rows
            .iter()
            .filter(|c| {
                if !self.show_tcp && c.proto.starts_with("TCP") {
                    return false;
                }
                if !self.show_udp && c.proto.starts_with("UDP") {
                    return false;
                }
                if self.listening_only && !c.listening {
                    return false;
                }
                if f.is_empty() {
                    return true;
                }
                c.proto.to_lowercase().contains(&f)
                    || c.local.to_lowercase().contains(&f)
                    || c.remote.to_lowercase().contains(&f)
                    || c.state.to_lowercase().contains(&f)
                    || c.process.to_lowercase().contains(&f)
                    || c.pid.to_string().contains(&f)
            })
            .cloned()
            .collect();

        let (sort, asc) = (self.sort, self.asc);
        view.sort_by(|a, b| {
            let o = match sort {
                SortCol::Proto => a.proto.cmp(&b.proto),
                SortCol::Local => a.local.cmp(&b.local),
                SortCol::Remote => a.remote.cmp(&b.remote),
                SortCol::Service => a.service.cmp(&b.service),
                SortCol::State => a.state.cmp(&b.state),
                SortCol::Pid => a.pid.cmp(&b.pid),
                SortCol::Process => a.process.to_lowercase().cmp(&b.process.to_lowercase()),
            };
            if asc { o } else { o.reverse() }
        });

        egui::Panel::bottom("status").resizable(false).show_inside(ui, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(format!("{} shown / {} sockets", view.len(), self.rows.len()));
                ui.separator();
                let listen = self.rows.iter().filter(|c| c.listening).count();
                ui.label(format!("{listen} listening"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label("UDP·QUIC? = guess")
                        .on_hover_text("QUIC runs over UDP and isn't detectable exactly at the socket level. Rows on UDP port 443/80 are flagged as a guess.");
                });
            });
            ui.add_space(2.0);
        });

        // resolver is a cheap Arc clone, so the table can borrow it alongside &mut self.
        let now = Instant::now();
        let resolver = self.resolver.clone();
        // Take seen out so the table can borrow it alongside &mut self.
        let seen = std::mem::take(&mut self.seen);
        let kill: Cell<Option<u32>> = Cell::new(None);
        let reveal: Cell<Option<u32>> = Cell::new(None);
        self.table(ui, &view, now, &seen, &resolver, &kill, &reveal);
        self.seen = seen;
        if let Some(pid) = kill.get() {
            self.kill_pid(pid);
        }
        if let Some(pid) = reveal.get() {
            self.reveal_pid(pid);
        }

        // Keep repainting so auto-refresh ticks without mouse input.
        if self.auto {
            ui.ctx().request_repaint_after(Duration::from_millis(300));
        }
    }
}
