//! Bluetooth HCI packets, as captured in btsnoop files and pcap's
//! BLUETOOTH_HCI_H4 link types: commands (opcode group and command, named
//! for the common ones), events (Command Complete and Command Status with
//! the opcode they answer, LE Meta advertising reports with their AD
//! structures), ACL data with the L2CAP header (signaling commands, ATT
//! opcodes), SCO and ISO data. Fields are little-endian; Bluetooth device
//! addresses are shown most significant byte first, as usual.

use super::dec::{Dec, Ix};
use crate::fields::Endian;
use crate::value::{EnumTable, lookup};

pub const H4_TYPES: EnumTable = &[
    (1, "Command"),
    (2, "ACL data"),
    (3, "SCO data"),
    (4, "Event"),
    (5, "ISO data"),
];

const OGFS: EnumTable = &[
    (1, "Link control"),
    (2, "Link policy"),
    (3, "Controller & baseband"),
    (4, "Informational parameters"),
    (5, "Status parameters"),
    (6, "Testing"),
    (8, "LE controller"),
    (0x3f, "Vendor specific"),
];

const OPCODES: EnumTable = &[
    (0x0401, "Inquiry"),
    (0x0402, "Inquiry Cancel"),
    (0x0405, "Create Connection"),
    (0x0406, "Disconnect"),
    (0x0409, "Accept Connection Request"),
    (0x040b, "Link Key Request Reply"),
    (0x0411, "Authentication Requested"),
    (0x0413, "Set Connection Encryption"),
    (0x0419, "Remote Name Request"),
    (0x041b, "Read Remote Supported Features"),
    (0x041d, "Read Remote Version Information"),
    (0x0c01, "Set Event Mask"),
    (0x0c03, "Reset"),
    (0x0c05, "Set Event Filter"),
    (0x0c13, "Write Local Name"),
    (0x0c14, "Read Local Name"),
    (0x0c16, "Write Connection Accept Timeout"),
    (0x0c18, "Write Page Timeout"),
    (0x0c1a, "Write Scan Enable"),
    (0x0c1e, "Write Inquiry Scan Activity"),
    (0x0c23, "Read Class of Device"),
    (0x0c24, "Write Class of Device"),
    (0x0c45, "Write Inquiry Mode"),
    (0x0c52, "Write Extended Inquiry Response"),
    (0x0c56, "Write Simple Pairing Mode"),
    (0x0c63, "Set Event Mask Page 2"),
    (0x0c6d, "Write LE Host Supported"),
    (0x0c7a, "Write Secure Connections Host Support"),
    (0x1001, "Read Local Version Information"),
    (0x1002, "Read Local Supported Commands"),
    (0x1003, "Read Local Supported Features"),
    (0x1004, "Read Local Extended Features"),
    (0x1005, "Read Buffer Size"),
    (0x1009, "Read BD_ADDR"),
    (0x1405, "Read RSSI"),
    (0x2001, "LE Set Event Mask"),
    (0x2002, "LE Read Buffer Size"),
    (0x2003, "LE Read Local Supported Features"),
    (0x2005, "LE Set Random Address"),
    (0x2006, "LE Set Advertising Parameters"),
    (0x2007, "LE Read Advertising Physical Channel Tx Power"),
    (0x2008, "LE Set Advertising Data"),
    (0x2009, "LE Set Scan Response Data"),
    (0x200a, "LE Set Advertising Enable"),
    (0x200b, "LE Set Scan Parameters"),
    (0x200c, "LE Set Scan Enable"),
    (0x200d, "LE Create Connection"),
    (0x200e, "LE Create Connection Cancel"),
    (0x200f, "LE Read Filter Accept List Size"),
    (0x2010, "LE Clear Filter Accept List"),
    (0x2011, "LE Add Device To Filter Accept List"),
    (0x2013, "LE Connection Update"),
    (0x2016, "LE Read Remote Features"),
    (0x2017, "LE Encrypt"),
    (0x2018, "LE Rand"),
    (0x2019, "LE Enable Encryption"),
    (0x201c, "LE Read Supported States"),
    (0x2022, "LE Set Data Length"),
    (0x2027, "LE Add Device To Resolving List"),
    (0x2029, "LE Clear Resolving List"),
    (0x202d, "LE Set Address Resolution Enable"),
    (0x2031, "LE Set Default PHY"),
    (0x2036, "LE Set Extended Advertising Parameters"),
    (0x2037, "LE Set Extended Advertising Data"),
    (0x2039, "LE Set Extended Advertising Enable"),
    (0x2041, "LE Set Extended Scan Parameters"),
    (0x2042, "LE Set Extended Scan Enable"),
    (0x2043, "LE Extended Create Connection"),
];

const EVENTS: EnumTable = &[
    (0x01, "Inquiry Complete"),
    (0x02, "Inquiry Result"),
    (0x03, "Connection Complete"),
    (0x04, "Connection Request"),
    (0x05, "Disconnection Complete"),
    (0x06, "Authentication Complete"),
    (0x07, "Remote Name Request Complete"),
    (0x08, "Encryption Change"),
    (0x0b, "Read Remote Supported Features Complete"),
    (0x0c, "Read Remote Version Information Complete"),
    (0x0e, "Command Complete"),
    (0x0f, "Command Status"),
    (0x10, "Hardware Error"),
    (0x13, "Number of Completed Packets"),
    (0x16, "PIN Code Request"),
    (0x17, "Link Key Request"),
    (0x18, "Link Key Notification"),
    (0x1b, "Max Slots Change"),
    (0x22, "Inquiry Result with RSSI"),
    (0x23, "Read Remote Extended Features Complete"),
    (0x2f, "Extended Inquiry Result"),
    (0x30, "Encryption Key Refresh Complete"),
    (0x31, "IO Capability Request"),
    (0x32, "IO Capability Response"),
    (0x33, "User Confirmation Request"),
    (0x36, "Simple Pairing Complete"),
    (0x3e, "LE Meta"),
    (0xff, "Vendor specific"),
];

const LE_SUBEVENTS: EnumTable = &[
    (0x01, "LE Connection Complete"),
    (0x02, "LE Advertising Report"),
    (0x03, "LE Connection Update Complete"),
    (0x04, "LE Read Remote Features Complete"),
    (0x05, "LE Long Term Key Request"),
    (0x06, "LE Remote Connection Parameter Request"),
    (0x07, "LE Data Length Change"),
    (0x0a, "LE Enhanced Connection Complete"),
    (0x0c, "LE PHY Update Complete"),
    (0x0d, "LE Extended Advertising Report"),
];

const STATUS: EnumTable = &[
    (0x00, "Success"),
    (0x01, "Unknown HCI command"),
    (0x02, "Unknown connection identifier"),
    (0x03, "Hardware failure"),
    (0x04, "Page timeout"),
    (0x05, "Authentication failure"),
    (0x06, "PIN or key missing"),
    (0x07, "Memory capacity exceeded"),
    (0x08, "Connection timeout"),
    (0x0c, "Command disallowed"),
    (0x12, "Invalid HCI command parameters"),
    (0x13, "Remote user terminated connection"),
    (0x16, "Connection terminated by local host"),
    (0x3e, "Connection failed to be established"),
];

const ADV_TYPES: EnumTable = &[
    (0, "ADV_IND"),
    (1, "ADV_DIRECT_IND"),
    (2, "ADV_SCAN_IND"),
    (3, "ADV_NONCONN_IND"),
    (4, "SCAN_RSP"),
];

const ADDRESS_TYPES: EnumTable = &[
    (0, "public"),
    (1, "random"),
    (2, "public identity"),
    (3, "random identity"),
];

const AD_TYPES: EnumTable = &[
    (0x01, "Flags"),
    (0x02, "Incomplete list of 16-bit service UUIDs"),
    (0x03, "Complete list of 16-bit service UUIDs"),
    (0x06, "Incomplete list of 128-bit service UUIDs"),
    (0x07, "Complete list of 128-bit service UUIDs"),
    (0x08, "Shortened local name"),
    (0x09, "Complete local name"),
    (0x0a, "Tx power level"),
    (0x16, "Service data (16-bit UUID)"),
    (0x19, "Appearance"),
    (0xff, "Manufacturer specific data"),
];

const L2CAP_CIDS: EnumTable = &[
    (1, "Signaling"),
    (2, "Connectionless"),
    (4, "Attribute protocol"),
    (5, "LE signaling"),
    (6, "Security manager"),
];

const L2CAP_CODES: EnumTable = &[
    (0x01, "Command Reject"),
    (0x02, "Connection Request"),
    (0x03, "Connection Response"),
    (0x04, "Configure Request"),
    (0x05, "Configure Response"),
    (0x06, "Disconnection Request"),
    (0x07, "Disconnection Response"),
    (0x08, "Echo Request"),
    (0x09, "Echo Response"),
    (0x0a, "Information Request"),
    (0x0b, "Information Response"),
    (0x12, "Connection Parameter Update Request"),
    (0x13, "Connection Parameter Update Response"),
    (0x14, "LE Credit Based Connection Request"),
    (0x15, "LE Credit Based Connection Response"),
    (0x16, "Flow Control Credit"),
];

const INFO_TYPES: EnumTable = &[
    (1, "Connectionless MTU"),
    (2, "Extended features mask"),
    (3, "Fixed channels supported"),
];

const ATT_OPCODES: EnumTable = &[
    (0x01, "Error Response"),
    (0x02, "Exchange MTU Request"),
    (0x03, "Exchange MTU Response"),
    (0x04, "Find Information Request"),
    (0x05, "Find Information Response"),
    (0x06, "Find By Type Value Request"),
    (0x07, "Find By Type Value Response"),
    (0x08, "Read By Type Request"),
    (0x09, "Read By Type Response"),
    (0x0a, "Read Request"),
    (0x0b, "Read Response"),
    (0x0c, "Read Blob Request"),
    (0x0d, "Read Blob Response"),
    (0x10, "Read By Group Type Request"),
    (0x11, "Read By Group Type Response"),
    (0x12, "Write Request"),
    (0x13, "Write Response"),
    (0x1b, "Handle Value Notification"),
    (0x1d, "Handle Value Indication"),
    (0x1e, "Handle Value Confirmation"),
    (0x52, "Write Command"),
];

/// A Bluetooth device address (stored least significant byte first).
fn bd_addr(b: &mut Dec, p: Ix, name: &'static str, at: usize) -> String {
    let s = b
        .bytes(at, 6)
        .map(|x| {
            x.iter()
                .rev()
                .map(|v| format!("{v:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        })
        .unwrap_or_default();
    let shown = s.clone();
    b.text(p, name, at, 6, || shown);
    s
}

fn opcode_name(op: u64) -> String {
    lookup(OPCODES, op).map_or_else(
        || {
            format!(
                "{} command {:#05x}",
                lookup(OGFS, op >> 10).unwrap_or("Unknown group"),
                op & 0x3ff
            )
        },
        str::to_owned,
    )
}

fn opcode_field(b: &mut Dec, p: Ix, at: usize) -> u64 {
    let op = b.numx(p, "Opcode", at, 2).unwrap_or(0);
    let name = opcode_name(op);
    b.tail(|n| {
        n.summary(format!(
            "{name} (OGF {:#04x}, OCF {:#05x})",
            op >> 10,
            op & 0x3ff
        ))
    });
    op
}

/// An HCI packet of type `kind` (H4 indicator values) at `off..end`;
/// returns the end of what was accounted for.
pub fn packet(b: &mut Dec, p: Ix, kind: u8, off: usize, end: usize) -> usize {
    let saved = b.endian;
    b.endian = Endian::Little;
    let used = match kind {
        1 => command(b, p, off, end),
        4 => event(b, p, off, end),
        2 => acl(b, p, off, end),
        3 | 5 => {
            let iso = kind == 5;
            let n = if iso { 4 } else { 3 };
            if end.saturating_sub(off) >= n {
                let ix = b.group(
                    p,
                    if iso { "HCI ISO data" } else { "HCI SCO data" },
                    off,
                    end.saturating_sub(off),
                );
                let h = b.numx(ix, "Handle / flags", off, 2).unwrap_or(0);
                b.num(
                    ix,
                    "Data length",
                    off.saturating_add(2),
                    n.saturating_sub(2),
                );
                b.data(ix, "Data", off.saturating_add(n), end);
                let what = if iso { "ISO" } else { "SCO" };
                b.summary(ix, || format!("handle {:#05x}", h & 0x0fff));
                b.set_info("HCI", || {
                    format!("HCI {what} data, handle {:#05x}", h & 0x0fff)
                });
                end
            } else {
                off
            }
        }
        _ => off,
    };
    b.endian = saved;
    used
}

fn command(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 3 {
        return off;
    }
    let plen = usize::from(b.u8(off.saturating_add(2)).unwrap_or(0));
    let cend = off.saturating_add(3).saturating_add(plen).min(end);
    let ix = b.group(p, "HCI command", off, cend.saturating_sub(off));
    let op = opcode_field(b, ix, off);
    b.num(ix, "Parameter length", off.saturating_add(2), 1);
    let at = off.saturating_add(3);
    match op {
        0x200c if plen >= 2 => {
            b.num(ix, "Enable", at, 1);
            b.num(ix, "Filter duplicates", at.saturating_add(1), 1);
        }
        0x200a | 0x0c56 | 0x0c1a if plen >= 1 => {
            b.num(ix, "Enable", at, 1);
        }
        0x0406 if plen >= 3 => {
            b.numx(ix, "Connection handle", at, 2);
            b.enm(ix, "Reason", at.saturating_add(2), 1, STATUS);
        }
        0x0c13 => {
            let name = String::from_utf8_lossy(b.range(at, cend))
                .trim_end_matches('\0')
                .to_owned();
            b.text(ix, "Local name", at, cend.saturating_sub(at), || name);
        }
        _ => {
            if at < cend {
                b.raw(ix, "Parameters", at, cend.saturating_sub(at));
            }
        }
    }
    let name = opcode_name(op);
    let shown = name.clone();
    b.summary(ix, || shown);
    b.set_info("HCI", || format!("HCI command {name}"));
    cend
}

fn event(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 2 {
        return off;
    }
    let plen = usize::from(b.u8(off.saturating_add(1)).unwrap_or(0));
    let eend = off.saturating_add(2).saturating_add(plen).min(end);
    let ix = b.group(p, "HCI event", off, eend.saturating_sub(off));
    let code = b.enm(ix, "Event code", off, 1, EVENTS).unwrap_or(0);
    b.num(ix, "Parameter length", off.saturating_add(1), 1);
    let at = off.saturating_add(2);
    let mut name = lookup(EVENTS, code).map_or_else(|| format!("event {code:#04x}"), str::to_owned);
    match code {
        0x0e if plen >= 3 => {
            b.num(ix, "Number of allowed command packets", at, 1);
            let op = opcode_field(b, ix, at.saturating_add(1));
            name = format!("{name} ({})", opcode_name(op));
            let r = at.saturating_add(3);
            if r < eend {
                let g = b.group(ix, "Return parameters", r, eend.saturating_sub(r));
                b.enm(g, "Status", r, 1, STATUS);
                let r1 = r.saturating_add(1);
                match op {
                    0x1009 if eend.saturating_sub(r1) >= 6 => {
                        let a = bd_addr(b, g, "BD_ADDR", r1);
                        b.summary(g, || a);
                    }
                    0x1001 if eend.saturating_sub(r1) >= 8 => {
                        b.num(g, "HCI version", r1, 1);
                        b.numx(g, "HCI revision", r1.saturating_add(1), 2);
                        b.num(g, "LMP version", r1.saturating_add(3), 1);
                        b.numx(g, "Manufacturer", r1.saturating_add(4), 2);
                        b.numx(g, "LMP subversion", r1.saturating_add(6), 2);
                    }
                    _ => {
                        if r1 < eend {
                            b.raw(g, "Data", r1, eend.saturating_sub(r1));
                        }
                    }
                }
            }
        }
        0x0f if plen >= 4 => {
            b.enm(ix, "Status", at, 1, STATUS);
            b.num(
                ix,
                "Number of allowed command packets",
                at.saturating_add(1),
                1,
            );
            let op = opcode_field(b, ix, at.saturating_add(2));
            name = format!("{name} ({})", opcode_name(op));
        }
        0x05 if plen >= 4 => {
            b.enm(ix, "Status", at, 1, STATUS);
            b.numx(ix, "Connection handle", at.saturating_add(1), 2);
            b.enm(ix, "Reason", at.saturating_add(3), 1, STATUS);
        }
        0x3e if plen >= 1 => {
            let sub = b.enm(ix, "Subevent", at, 1, LE_SUBEVENTS).unwrap_or(0);
            name = lookup(LE_SUBEVENTS, sub).map_or(name, str::to_owned);
            if sub == 2 {
                let n = b
                    .num(ix, "Number of reports", at.saturating_add(1), 1)
                    .unwrap_or(0);
                let mut r = at.saturating_add(2);
                for _ in 0..n {
                    if eend.saturating_sub(r) < 10 {
                        break;
                    }
                    let dl = usize::from(b.u8(r.saturating_add(8)).unwrap_or(0));
                    let rlen = 10usize.saturating_add(dl).min(eend.saturating_sub(r));
                    let g = b.group(ix, "Advertising report", r, rlen);
                    b.enm(g, "Event type", r, 1, ADV_TYPES);
                    b.enm(g, "Address type", r.saturating_add(1), 1, ADDRESS_TYPES);
                    let a = bd_addr(b, g, "Address", r.saturating_add(2));
                    b.num(g, "Data length", r.saturating_add(8), 1);
                    let d = r.saturating_add(9);
                    ad_structures(b, g, d, d.saturating_add(dl).min(eend));
                    let rssi_at = d.saturating_add(dl);
                    let rssi = b.u8(rssi_at).map(|v| i64::from(v as i8));
                    if let Some(v) = rssi {
                        b.add(g, "RSSI", rssi_at, 1, |n| {
                            n.value(crate::formats::util::val::int(v, 8)).summary("dBm")
                        });
                    }
                    b.summary(g, || a);
                    r = r.saturating_add(rlen);
                }
            } else if at.saturating_add(1) < eend {
                b.raw(
                    ix,
                    "Parameters",
                    at.saturating_add(1),
                    eend.saturating_sub(at.saturating_add(1)),
                );
            }
        }
        _ => {
            if at < eend {
                b.raw(ix, "Parameters", at, eend.saturating_sub(at));
            }
        }
    }
    let shown = name.clone();
    b.summary(ix, || shown);
    b.set_info("HCI", || format!("HCI event {name}"));
    eend
}

/// Advertising data: length, type, data.
fn ad_structures(b: &mut Dec, p: Ix, off: usize, end: usize) {
    let mut at = off;
    while at < end {
        let len = usize::from(b.u8(at).unwrap_or(0));
        if len == 0 {
            b.data(p, "Padding", at, end);
            break;
        }
        let send = at.saturating_add(1).saturating_add(len).min(end);
        let t = b.u8(at.saturating_add(1)).unwrap_or(0);
        let name = lookup(AD_TYPES, t.into()).unwrap_or("AD structure");
        let g = b.group(p, name, at, send.saturating_sub(at));
        b.num(g, "Length", at, 1);
        b.enm(g, "Type", at.saturating_add(1), 1, AD_TYPES);
        let d = at.saturating_add(2);
        match t {
            0x08 | 0x09 => {
                let s = String::from_utf8_lossy(b.range(d, send)).into_owned();
                let shown = s.clone();
                b.text(g, "Name", d, send.saturating_sub(d), || shown);
                b.summary(g, || s);
            }
            _ => {
                if d < send {
                    b.raw(g, "Data", d, send.saturating_sub(d));
                }
            }
        }
        at = send;
    }
}

fn acl(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 4 {
        return off;
    }
    let h = b.u16(off).unwrap_or(0);
    let len = usize::from(b.u16(off.saturating_add(2)).unwrap_or(0));
    let aend = off.saturating_add(4).saturating_add(len).min(end);
    let ix = b.group(p, "HCI ACL data", off, 4);
    b.numx(ix, "Handle / flags", off, 2);
    let (handle, pb, bc) = (h & 0x0fff, (h >> 12) & 3, h >> 14);
    b.tail(|n| {
        n.summary(format!(
            "handle {handle:#05x}, {}, broadcast {bc}",
            match pb {
                0 => "first non-flushable fragment",
                1 => "continuing fragment",
                2 => "first flushable fragment",
                _ => "complete",
            }
        ))
    });
    b.num(ix, "Data total length", off.saturating_add(2), 2);
    b.summary(ix, || format!("handle {handle:#05x}, {len} bytes"));
    b.set_info("HCI", || format!("HCI ACL data, handle {handle:#05x}"));
    let at = off.saturating_add(4);
    if pb == 1 || aend.saturating_sub(at) < 4 {
        return b.data(p, "ACL payload", at, aend);
    }
    // L2CAP basic header.
    let llen = usize::from(b.u16(at).unwrap_or(0));
    let cid = b.u16(at.saturating_add(2)).unwrap_or(0);
    let lend = at.saturating_add(4).saturating_add(llen).min(aend);
    let l = b.group(p, "L2CAP", at, lend.saturating_sub(at));
    b.num(l, "Length", at, 2);
    b.enm(l, "Channel ID", at.saturating_add(2), 2, L2CAP_CIDS);
    let body = at.saturating_add(4);
    let cname = lookup(L2CAP_CIDS, cid.into()).unwrap_or("dynamic channel");
    let mut what = cname.to_owned();
    match cid {
        1 | 5 if lend.saturating_sub(body) >= 4 => {
            let code = b.enm(l, "Code", body, 1, L2CAP_CODES).unwrap_or(0);
            b.num(l, "Identifier", body.saturating_add(1), 1);
            b.num(l, "Command length", body.saturating_add(2), 2);
            let d = body.saturating_add(4);
            if code == 0x0a && lend.saturating_sub(d) >= 2 {
                b.enm(l, "Information type", d, 2, INFO_TYPES);
            } else if d < lend {
                b.raw(l, "Data", d, lend.saturating_sub(d));
            }
            what = lookup(L2CAP_CODES, code)
                .unwrap_or("signaling command")
                .to_owned();
        }
        4 if lend > body => {
            let op = b.enm(l, "ATT opcode", body, 1, ATT_OPCODES).unwrap_or(0);
            let d = body.saturating_add(1);
            if d < lend {
                b.raw(l, "Parameters", d, lend.saturating_sub(d));
            }
            what = format!("ATT {}", lookup(ATT_OPCODES, op).unwrap_or("opcode"));
        }
        _ => {
            b.data(l, "Payload", body, lend);
        }
    }
    let shown = what.clone();
    b.summary(l, || format!("{cname}, {shown}"));
    b.set_info("L2CAP", || format!("L2CAP {what}"));
    lend
}
