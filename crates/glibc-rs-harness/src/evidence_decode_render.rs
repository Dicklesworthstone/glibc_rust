//! Deterministic rendering for offline evidence decode proofs.
//!
//! Bead: `bd-pc4`
//!
//! The primary artifact is JSON (`DecodeReport`), but we also provide a stable
//! table render for human inspection and diffs (optionally through FrankentUI).

use crate::evidence_decode::{DecodeReport, DecodeStatus};

#[must_use]
pub fn render_plain(report: &DecodeReport) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();

    let w_epoch: usize = 16;
    let w_seed: usize = 16;
    let w_fm: usize = 5;
    let w_kr: usize = 7;
    let w_recs: usize = 11;
    let w_hash: usize = 7;
    let w_dec: usize = 7;
    let w_rep: usize = 7;
    let w_status: usize = 6;
    let w_notes: usize = 48;

    writeln!(
        out,
        "evidence decode report (epochs={})",
        report.epochs.len()
    )
    .ok();

    writeln!(
        out,
        "{:<w_epoch$} {:<w_seed$} {:<w_fm$} {:<w_kr$} {:<w_recs$} {:<w_hash$} {:<w_dec$} {:<w_rep$} {:<w_status$} notes",
        "epoch",
        "seed",
        "f/m",
        "k/r",
        "sys/rep/tot",
        "p/c",
        "dec/mis",
        "ver/mis",
        "status",
    )
    .ok();

    let sep_len = w_epoch
        + 1
        + w_seed
        + 1
        + w_fm
        + 1
        + w_kr
        + 1
        + w_recs
        + 1
        + w_hash
        + 1
        + w_dec
        + 1
        + w_rep
        + 1
        + w_status
        + 1
        + w_notes;
    writeln!(out, "{}", "-".repeat(sep_len)).ok();

    for epoch in &report.epochs {
        let epoch_hex = format!("{:016X}", epoch.epoch_id);
        let seed_hex = format!("{:016X}", epoch.seed);
        let fm = format!("{}/{}", epoch.family, epoch.mode);
        let kr = format!("{}/{}", epoch.k_source, epoch.r_repair);
        let recs = format!(
            "{}/{}/{}",
            epoch.systematic_records, epoch.repair_records, epoch.records_total
        );
        let hash = format!(
            "{}/{}",
            epoch.payload_hash_mismatches, epoch.chain_hash_mismatches
        );
        let dec = format!("{}/{}", epoch.decoded_systematic, epoch.missing_systematic);
        let rep = format!(
            "{}/{}",
            epoch.verified_repairs, epoch.repair_payload_mismatches
        );
        let status = match epoch.status {
            DecodeStatus::Success => "OK",
            DecodeStatus::Partial => "PART",
            DecodeStatus::Failed => "FAIL",
        };

        let notes = if epoch.notes.is_empty() {
            String::new()
        } else {
            epoch.notes.join(",")
        };

        writeln!(
            out,
            "{:<w_epoch$} {:<w_seed$} {:<w_fm$} {:<w_kr$} {:<w_recs$} {:<w_hash$} {:<w_dec$} {:<w_rep$} {:<w_status$} {}",
            truncate(&epoch_hex, w_epoch),
            truncate(&seed_hex, w_seed),
            truncate(&fm, w_fm),
            truncate(&kr, w_kr),
            truncate(&recs, w_recs),
            truncate(&hash, w_hash),
            truncate(&dec, w_dec),
            truncate(&rep, w_rep),
            status,
            truncate(&notes, w_notes),
        )
        .ok();
    }

    out
}

fn truncate(s: &str, width: usize) -> String {
    if s.len() <= width {
        return s.to_string();
    }
    if width <= 3 {
        return s[..width].to_string();
    }
    format!("{}...", &s[..(width - 3)])
}

#[cfg(feature = "frankentui-ui")]
#[must_use]
pub fn render_ftui(report: &DecodeReport, ansi: bool, width: u16) -> String {
    use ftui_core::geometry::Rect;
    use ftui_layout::Constraint;
    use ftui_render::cell::PackedRgba;
    use ftui_render::frame::Frame;
    use ftui_render::grapheme_pool::GraphemePool;
    use ftui_style::Style;
    use ftui_widgets::Widget;
    use ftui_widgets::block::Block;
    use ftui_widgets::borders::{BorderType, Borders};
    use ftui_widgets::table::{Row, Table};

    let height = (report.epochs.len() as u16).saturating_add(4);
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(width, height, &mut pool);

    let header = Row::new([
        "epoch",
        "seed",
        "f/m",
        "k/r",
        "sys/rep/tot",
        "p/c",
        "dec/mis",
        "ver/mis",
        "status",
        "notes",
    ])
    .style(Style::new().bold());

    let rows: Vec<Row> = report
        .epochs
        .iter()
        .map(|epoch| {
            let epoch_hex = format!("{:016X}", epoch.epoch_id);
            let seed_hex = format!("{:016X}", epoch.seed);
            let fm = format!("{}/{}", epoch.family, epoch.mode);
            let kr = format!("{}/{}", epoch.k_source, epoch.r_repair);
            let recs = format!(
                "{}/{}/{}",
                epoch.systematic_records, epoch.repair_records, epoch.records_total
            );
            let hash = format!(
                "{}/{}",
                epoch.payload_hash_mismatches, epoch.chain_hash_mismatches
            );
            let dec = format!("{}/{}", epoch.decoded_systematic, epoch.missing_systematic);
            let rep = format!(
                "{}/{}",
                epoch.verified_repairs, epoch.repair_payload_mismatches
            );
            let status = match epoch.status {
                DecodeStatus::Success => "OK",
                DecodeStatus::Partial => "PART",
                DecodeStatus::Failed => "FAIL",
            };

            let notes = if epoch.notes.is_empty() {
                String::new()
            } else {
                epoch.notes.join(",")
            };

            let style = match epoch.status {
                DecodeStatus::Success => Style::new().fg(PackedRgba::rgb(0, 255, 0)),
                DecodeStatus::Partial => Style::new().fg(PackedRgba::rgb(255, 255, 0)),
                DecodeStatus::Failed => Style::new().fg(PackedRgba::RED).bold(),
            };

            Row::new([
                epoch_hex.as_str(),
                seed_hex.as_str(),
                fm.as_str(),
                kr.as_str(),
                recs.as_str(),
                hash.as_str(),
                dec.as_str(),
                rep.as_str(),
                status,
                notes.as_str(),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Fixed(16),
            Constraint::Fixed(16),
            Constraint::Fixed(5),
            Constraint::Fixed(7),
            Constraint::Fixed(11),
            Constraint::Fixed(7),
            Constraint::Fixed(7),
            Constraint::Fixed(7),
            Constraint::Fixed(6),
            Constraint::Fixed(30),
        ],
    )
    .header(header)
    .block(
        Block::new()
            .title(" evidence decode report ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded),
    )
    .column_spacing(1);

    let area = Rect::from_size(width, height);
    table.render(area, &mut frame);

    if ansi {
        ftui_harness::buffer_to_ansi(&frame.buffer)
    } else {
        ftui_harness::buffer_to_text(&frame.buffer)
    }
}
