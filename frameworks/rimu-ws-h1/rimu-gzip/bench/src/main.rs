//! One-shot DEFLATE of in-memory slices: output size and single-core throughput of every
//! rimu-gzip level, the original rimu-ws encoder, libdeflate, sirocco, zlib-rs and miniz_oxide.
//!
//! Usage: `bench <corpus-dir> [--gzip] [--codecs a,b,..] [--sizes n|full,..] [--files a,..]
//! [--csv path]`. Codec filters match name prefixes. Every output is checked to inflate to its
//! input with libdeflate. Raw DEFLATE streams are compared by default (no framing, no checksum);
//! `--gzip` compares gzip members instead (miniz_oxide has no gzip writer and is skipped).
//! `BENCH_MS` sets the length of one timed batch (default 20), `BENCH_SAMPLES` the batches per
//! row (default 9); the median batch is reported.

mod legacy;

use libdeflater::{CompressionLvl, Compressor, Decompressor};
use rimu_gzip::{Encoder, Format, Level};
use std::{collections::BTreeMap, fmt::Write as _, hint::black_box, time::Instant};

/// The size classes: every corpus file is cut to each size it reaches; `FULL` is the whole file.
const SIZES: &[usize] = &[256, 1024, 4096, 16 << 10, 64 << 10, 256 << 10, FULL];
/// The size class of whole files.
const FULL: usize = usize::MAX;

/// One measured row.
struct Row {
  file: String,
  size: usize,
  codec: String,
  out: usize,
  mb_s: f64,
}

/// Median nanoseconds per call over `samples` timed batches of about `batch_ms` each.
fn time(batch_ms: f64, samples: usize, mut f: impl FnMut()) -> f64 {
  let warm = Instant::now();
  let mut n = 0u64;
  while warm.elapsed().as_secs_f64() * 1e3 < batch_ms {
    f();
    n += 1;
  }
  let per = warm.elapsed().as_nanos() as f64 / n as f64;
  let iters = ((batch_ms * 1e6 / per) as u64).max(1);
  let mut runs: Vec<f64> = (0..samples)
    .map(|_| {
      let t = Instant::now();
      for _ in 0..iters {
        f();
      }
      t.elapsed().as_nanos() as f64 / iters as f64
    })
    .collect();
  runs.sort_by(f64::total_cmp);
  runs[runs.len() / 2]
}

/// A codec: name and a function appending the compressed input to the vector.
type Codec<'a> = (String, Box<dyn FnMut(&[u8], &mut Vec<u8>) + 'a>);

/// Every codec, writing raw DEFLATE (or gzip with `gzip`).
fn codecs(gzip: bool) -> Vec<Codec<'static>> {
  let mut list: Vec<Codec<'static>> = Vec::new();
  let format = if gzip { Format::Gzip } else { Format::Raw };
  for level in 0..=9 {
    let mut encoder = Encoder::with_level(Level::new(level).unwrap());
    list.push((format!("rimu-{level}"), Box::new(move |i, o| encoder.encode(format, i, o))));
  }
  let mut old = legacy::GzipEncoder::new();
  list.push(("rimu-ws-old".into(), Box::new(move |i, o| old.encode(i, o, !gzip))));
  for level in [1, 4, 6, 9] {
    let mut c = Compressor::new(CompressionLvl::new(level).unwrap());
    list.push((
      format!("libdeflate-{level}"),
      Box::new(move |i, o| {
        let start = o.len();
        let bound =
          if gzip { c.gzip_compress_bound(i.len()) } else { c.deflate_compress_bound(i.len()) };
        o.resize(start + bound, 0);
        let n = if gzip {
          c.gzip_compress(i, &mut o[start..]).unwrap()
        } else {
          c.deflate_compress(i, &mut o[start..]).unwrap()
        };
        o.truncate(start + n);
      }),
    ));
  }
  for level in [1, 4, 6, 8, 9] {
    let format = if gzip { sirocco::Format::Gzip } else { sirocco::Format::Deflate };
    let mut enc = sirocco::deflate::Encoder::new(format, sirocco::deflate::Level::new(level));
    list.push((
      format!("sirocco-{level}"),
      Box::new(move |i, o| {
        let start = o.len();
        o.resize(start + i.len() + 1024, 0);
        let mut filled = 0;
        loop {
          let p = enc.compress(i, &mut o[start + filled..], sirocco::deflate::Flush::Finish);
          filled += p.output.len();
          if p.done {
            break;
          }
          o.resize(o.len() + (i.len() / 2).max(4096), 0);
        }
        o.truncate(start + filled);
      }),
    ));
  }
  for level in [1, 6] {
    list.push((
      format!("zlib-rs-{level}"),
      Box::new(move |i, o| {
        let start = o.len();
        o.resize(start + i.len() + i.len() / 8 + 1024, 0);
        let mut config = zlib_rs::deflate::DeflateConfig::new(level);
        config.window_bits = if gzip { 31 } else { -15 };
        let (res, rc) = zlib_rs::deflate::compress_slice(&mut o[start..], i, config);
        assert_eq!(rc, zlib_rs::ReturnCode::Ok);
        let n = res.len();
        o.truncate(start + n);
      }),
    ));
  }
  if !gzip {
    for level in [1u8, 6] {
      list.push((
        format!("miniz-{level}"),
        Box::new(move |i, o| o.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(i, level))),
      ));
    }
  }
  list
}

/// The value of `--name` in `args`, split at commas.
fn list_arg(args: &[String], name: &str) -> Option<Vec<String>> {
  let i = args.iter().position(|a| a == name)?;
  Some(args.get(i + 1)?.split(',').map(str::to_owned).collect())
}

fn main() {
  let args: Vec<String> = std::env::args().skip(1).collect();
  let dir = args.first().expect("usage: bench <corpus-dir> [options]");
  let gzip = args.iter().any(|a| a == "--gzip");
  let codec_filter = list_arg(&args, "--codecs");
  let size_filter: Option<Vec<usize>> = list_arg(&args, "--sizes")
    .map(|v| v.iter().map(|s| if s == "full" { FULL } else { s.parse().unwrap() }).collect());
  let file_filter = list_arg(&args, "--files");
  let csv_path = list_arg(&args, "--csv").map(|v| v[0].clone());
  let env = |k: &str, d: f64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
  let (batch_ms, samples) = (env("BENCH_MS", 20.0), env("BENCH_SAMPLES", 9.0) as usize);
  let mut files: Vec<_> =
    std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_file()).collect();
  files.sort();
  let mut codecs = codecs(gzip);
  codecs.retain(|(name, _)| {
    codec_filter.as_ref().is_none_or(|f| f.iter().any(|p| name.starts_with(p.as_str())))
  });
  let mut dec = Decompressor::new();
  let mut rows = Vec::new();
  let mut csv = String::from("file,size,codec,out_bytes,ratio,ns,mb_s\n");
  println!("file,size,codec,out_bytes,ratio,ns,mb_s");
  for path in files {
    let data = std::fs::read(&path).unwrap();
    let file = path.file_name().unwrap().to_string_lossy().to_string();
    if file_filter.as_ref().is_some_and(|f| !f.iter().any(|p| file.starts_with(p.as_str()))) {
      continue;
    }
    for &class in SIZES {
      if class != FULL && class > data.len()
        || size_filter.as_ref().is_some_and(|f| !f.contains(&class))
      {
        continue;
      }
      let size = class.min(data.len());
      let input = &data[..size];
      let mut out = Vec::with_capacity(size + size / 8 + 4096);
      let mut back = vec![0u8; size];
      for (codec, f) in &mut codecs {
        out.clear();
        f(input, &mut out);
        let len = out.len();
        let n = if gzip {
          dec.gzip_decompress(&out, &mut back).unwrap()
        } else {
          dec.deflate_decompress(&out, &mut back).unwrap()
        };
        assert!(n == size && back == input, "{codec} {file} {size}: bad round trip");
        let ns = time(batch_ms, samples, || {
          out.clear();
          f(black_box(input), &mut out);
          black_box(&out);
        });
        let mb_s = size as f64 / ns * 1e3;
        let label = if class == FULL { "full".to_string() } else { size.to_string() };
        let line =
          format!("{file},{label},{codec},{len},{:.4},{ns:.0},{mb_s:.1}", len as f64 / size as f64);
        println!("{line}");
        let _ = writeln!(csv, "{line}");
        rows.push(Row { file: file.clone(), size: class, codec: codec.clone(), out: len, mb_s });
      }
    }
  }
  if let Some(path) = csv_path {
    std::fs::write(path, csv).unwrap();
  }
  summary(&rows, &codecs.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>());
}

/// Prints, per size class, the geometric means over the files of every codec's output size
/// relative to libdeflate level 6 and of its MB/s.
fn summary(rows: &[Row], codecs: &[String]) {
  let mut by: BTreeMap<(usize, &str), Vec<&Row>> = BTreeMap::new();
  for row in rows {
    by.entry((row.size, row.codec.as_str())).or_default().push(row);
  }
  let sizes: Vec<usize> =
    SIZES.iter().copied().filter(|s| rows.iter().any(|r| r.size == *s)).collect();
  println!("\n## Geometric means per size class (size relative to libdeflate-6; MB/s)\n");
  print!("| codec |");
  for s in &sizes {
    print!(" {} |", human(*s));
  }
  println!();
  print!("|---|");
  for _ in &sizes {
    print!("---|");
  }
  println!();
  for codec in codecs {
    print!("| {codec} |");
    for &s in &sizes {
      let Some(mine) = by.get(&(s, codec.as_str())) else {
        print!(" – |");
        continue;
      };
      let reference = by.get(&(s, "libdeflate-6"));
      let rel = reference.map(|r| {
        geomean(mine.iter().map(|m| {
          let base = r.iter().find(|x| x.file == m.file).unwrap();
          m.out as f64 / base.out as f64
        }))
      });
      let speed = geomean(mine.iter().map(|m| m.mb_s));
      match rel {
        Some(rel) => print!(" {:.3} @ {speed:.0} |", rel),
        None => print!(" {speed:.0} MB/s |"),
      }
    }
    println!();
  }
}

/// The geometric mean of `values`.
fn geomean(values: impl Iterator<Item = f64>) -> f64 {
  let (mut sum, mut n) = (0.0, 0);
  for v in values {
    sum += v.ln();
    n += 1;
  }
  (sum / n as f64).exp()
}

/// `size` as 256 B, 4 KB, 1 MB, or "whole files".
fn human(size: usize) -> String {
  match size {
    FULL => "whole files".into(),
    s if s >= 1 << 20 => format!("{} MB", s >> 20),
    s if s >= 1 << 10 => format!("{} KB", s >> 10),
    s => format!("{s} B"),
  }
}
