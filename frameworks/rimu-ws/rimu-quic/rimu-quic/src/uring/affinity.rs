//! The CPUs that the workers are pinned to ([`super::Pinning::Auto`]).

use alloc::{format, vec::Vec};

/// The CPUs that the process may run on, the first thread of each physical core first, then the
/// others. `None` without `/proc/self/status`.
pub(crate) fn cpu_order() -> Option<Vec<usize>> {
  let status = std::fs::read_to_string("/proc/self/status").ok()?;
  let list = status.lines().find_map(|el| el.strip_prefix("Cpus_allowed_list:"))?;
  let allowed = parse_list(list.trim())?;
  let first_of_core = |cpu: &usize| {
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
    std::fs::read_to_string(path).map_or(true, |siblings| {
      parse_list(siblings.trim()).and_then(|el| el.first().copied()).is_none_or(|el| el == *cpu)
    })
  };
  let (mut rslt, others): (Vec<usize>, Vec<usize>) = allowed.into_iter().partition(first_of_core);
  rslt.extend(others);
  Some(rslt)
}

/// A CPU list of the kernel (`0-5,12-17`), in increasing order. `None` if malformed.
pub(crate) fn parse_list(list: &str) -> Option<Vec<usize>> {
  let mut rslt = Vec::new();
  for item in list.split(',').filter(|el| !el.is_empty()) {
    match item.split_once('-') {
      Some((from, to)) => {
        let (from, to) = (from.parse::<usize>().ok()?, to.parse::<usize>().ok()?);
        if to < from || to - from > 4096 {
          return None;
        }
        rslt.extend(from..=to);
      }
      None => rslt.push(item.parse().ok()?),
    }
  }
  rslt.sort_unstable();
  rslt.dedup();
  Some(rslt)
}

#[cfg(test)]
mod tests {
  use super::parse_list;

  #[test]
  fn cpu_lists_parse() {
    assert_eq!(parse_list("0-2,5,12-13"), Some(alloc::vec![0, 1, 2, 5, 12, 13]));
    assert_eq!(parse_list("7"), Some(alloc::vec![7]));
    assert_eq!(parse_list(""), Some(alloc::vec![]));
    assert_eq!(parse_list("3-1"), None);
    assert_eq!(parse_list("a"), None);
  }
}
