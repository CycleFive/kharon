//! Choosing which typed value is the username and which are passwords.

use kharon_recording::Role;
use zeroize::Zeroizing;

use super::{Buffered, RawBody, RawElement};
use crate::marker::Marker;
use crate::strip::any_hit;

/// Everything known about one element: its first report, and the latest value typed into it.
pub(super) struct Elem {
    pub raw: RawElement,
    pub value: Zeroizing<String>,
    pub was_password: bool,
    pub shadow: bool,
    pub has_step: bool,
    /// Sequence numbers of the first and the latest value-bearing event.
    pub first_seq: u64,
    pub last_seq: u64,
}

impl Elem {
    fn form_key(&self) -> Option<(&str, u32)> {
        self.raw
            .form
            .as_ref()
            .map(|f| (self.raw.document_id.as_str(), f.index))
    }
}

/// One marker per element that holds a typed value, with the roles chosen.
pub(super) struct Resolved {
    pub markers: Vec<Marker>,
    pub username_elem: Option<usize>,
    pub username_marker: Option<usize>,
    pub password_marker: Option<usize>,
    pub multiple_passwords: bool,
}

impl Resolved {
    pub fn pair(&self) -> Option<(&Marker, &Marker)> {
        match (self.username_marker, self.password_marker) {
            (Some(u), Some(p)) => Some((self.markers.get(u)?, self.markers.get(p)?)),
            _ => None,
        }
    }
}

fn plain_marker(value: &str, role: Role) -> Marker {
    Marker::new(Zeroizing::new(value.to_owned()), role)
}

/// Whether `marker` occurs in the request's URL, authorization header or body, under any encoding.
fn carries(req: &Buffered, marker: &Marker) -> bool {
    let one = std::slice::from_ref(marker);
    any_hit(req.url.as_bytes(), one, None)
        || req
            .authorization
            .as_ref()
            .is_some_and(|a| any_hit(a, one, None))
        || matches!(&req.body, RawBody::Bytes(b) if any_hit(b, one, None))
}

/// The candidate typed in most recently before the first password input; failing that, the latest.
fn pick(cands: &[usize], elems: &[Elem], first_password_seq: Option<u64>) -> Option<usize> {
    cands
        .iter()
        .copied()
        .filter(|&i| first_password_seq.is_none_or(|s| elems[i].first_seq < s))
        .max_by_key(|&i| elems[i].last_seq)
        .or_else(|| cands.iter().copied().max_by_key(|&i| elems[i].last_seq))
}

pub(super) fn resolve(elems: &[Elem], reqs: &[Buffered]) -> Resolved {
    let password_values: Vec<&str> = {
        let mut seen: Vec<&str> = Vec::new();
        for e in elems
            .iter()
            .filter(|e| e.was_password && !e.value.is_empty())
        {
            if !seen.contains(&e.value.as_str()) {
                seen.push(e.value.as_str());
            }
        }
        seen
    };
    let multiple_passwords = password_values.len() > 1;
    let password_markers: Vec<Marker> = password_values
        .iter()
        .map(|v| plain_marker(v, Role::Password))
        .collect();
    let first_password_seq = elems
        .iter()
        .filter(|e| e.was_password)
        .map(|e| e.first_seq)
        .min();
    let cands: Vec<usize> = (0..elems.len())
        .filter(|&i| !elems[i].was_password && !elems[i].value.is_empty())
        .collect();
    let probes: Vec<(usize, Marker)> = cands
        .iter()
        .map(|&i| (i, plain_marker(&elems[i].value, Role::None)))
        .collect();
    let narrowed = |keep: &dyn Fn(usize, &Marker) -> bool| -> Vec<usize> {
        probes
            .iter()
            .filter(|(i, m)| keep(*i, m))
            .map(|(i, _)| *i)
            .collect()
    };

    let same_form = narrowed(&|i, _| {
        elems[i].form_key().is_some_and(|k| {
            elems
                .iter()
                .any(|p| p.was_password && p.form_key() == Some(k))
        })
    });
    let with_password = narrowed(&|_, m| {
        reqs.iter()
            .any(|r| carries(r, m) && password_markers.iter().any(|p| carries(r, p)))
    });
    let in_any_request = narrowed(&|_, m| reqs.iter().any(|r| carries(r, m)));

    let username_elem = [same_form, with_password, in_any_request, cands]
        .iter()
        .find_map(|level| pick(level, elems, first_password_seq));

    let mut markers = Vec::new();
    let (mut username_marker, mut password_marker) = (None, None);
    for (i, e) in elems.iter().enumerate() {
        if e.value.is_empty() {
            continue;
        }
        let role = if e.was_password {
            Role::Password
        } else if Some(i) == username_elem {
            Role::Username
        } else {
            Role::None
        };
        match role {
            Role::Username => username_marker = Some(markers.len()),
            Role::Password if password_marker.is_none() => password_marker = Some(markers.len()),
            Role::Password | Role::None => {}
        }
        markers.push(plain_marker(&e.value, role));
    }
    Resolved {
        markers,
        username_elem,
        username_marker,
        password_marker,
        multiple_passwords,
    }
}
