use crate::image::{valid_identifier, validate_ocr};
use crate::{ImportedImage, IngestionError, OcrPage, OcrRegion};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use wait_timeout::ChildExt;

pub const DEFAULT_MAX_OCR_OUTPUT_BYTES: usize = 20 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TesseractConfig {
    /// Absolute path to the application-packaged Tesseract executable.
    pub executable: PathBuf,
    /// Absolute path containing the application-packaged `.traineddata` files.
    pub tessdata_dir: PathBuf,
    /// Canonical packaged engine version used in provenance, e.g. `5.5.0`.
    pub engine_version: String,
    /// Tesseract language identifiers, normally `vie` and `eng`.
    pub languages: Vec<String>,
    pub page_segmentation_mode: u8,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

/// Runs Tesseract as an isolated child process over pipes, without plaintext temp files.
pub fn run_tesseract(
    imported: &ImportedImage,
    config: &TesseractConfig,
) -> Result<OcrPage, IngestionError> {
    validate_config(config)?;
    let languages = config.languages.join("+");
    let mut command = Command::new(&config.executable);
    command
        .arg("stdin")
        .arg("stdout")
        .arg("-l")
        .arg(&languages)
        .arg("--oem")
        .arg("1")
        .arg("--psm")
        .arg(config.page_segmentation_mode.to_string())
        .arg("tsv")
        .env("TESSDATA_PREFIX", &config.tessdata_dir)
        .env("OMP_THREAD_LIMIT", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| IngestionError::OcrUnavailable)?;
    let mut stdin = child.stdin.take().ok_or(IngestionError::OcrUnavailable)?;
    let stdout = child.stdout.take().ok_or(IngestionError::OcrUnavailable)?;
    let stderr = child.stderr.take().ok_or(IngestionError::OcrUnavailable)?;
    let input = imported.ocr_input_png.clone();
    let input_task = thread::spawn(move || stdin.write_all(&input));
    let max_output = config.max_output_bytes;
    let stdout_task = thread::spawn(move || read_capped(stdout, max_output));
    let stderr_limit = max_output.clamp(4_096, 256 * 1024);
    let stderr_task = thread::spawn(move || read_capped(stderr, stderr_limit));

    let status = match child.wait_timeout(config.timeout) {
        Ok(status) => status,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = join_input(input_task);
            let _ = stdout_task.join();
            let _ = stderr_task.join();
            return Err(IngestionError::OcrProcessFailed);
        }
    };
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = join_input(input_task);
        let _ = stdout_task.join();
        let _ = stderr_task.join();
        return Err(IngestionError::OcrTimeout);
    };
    let input_result = join_input(input_task);
    let output_result = join_output(stdout_task);
    let _stderr = join_output(stderr_task);
    if !status.success() {
        return Err(IngestionError::OcrProcessFailed);
    }
    input_result?;
    let output = output_result?;
    parse_tsv(imported, config, &output)
}

fn validate_config(config: &TesseractConfig) -> Result<(), IngestionError> {
    if !config.executable.is_absolute()
        || !config.executable.is_file()
        || !config.tessdata_dir.is_absolute()
        || !config.tessdata_dir.is_dir()
        || !valid_identifier(&config.engine_version)
        || config.languages.is_empty()
        || config
            .languages
            .iter()
            .any(|language| !valid_identifier(language))
        || !(1..=13).contains(&config.page_segmentation_mode)
        || config.timeout.is_zero()
        || config.max_output_bytes == 0
    {
        return Err(IngestionError::InvalidOcrConfiguration);
    }
    for language in &config.languages {
        if !config
            .tessdata_dir
            .join(format!("{language}.traineddata"))
            .is_file()
        {
            return Err(IngestionError::InvalidOcrConfiguration);
        }
    }
    Ok(())
}

fn read_capped(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, IngestionError> {
    let mut bytes = Vec::new();
    let mut exceeded = false;
    let mut chunk = [0u8; 8_192];
    loop {
        let count = reader
            .read(&mut chunk)
            .map_err(|_| IngestionError::OcrProcessFailed)?;
        if count == 0 {
            return if exceeded {
                Err(IngestionError::OcrOutputTooLarge)
            } else {
                Ok(bytes)
            };
        }
        if bytes.len().saturating_add(count) > limit {
            exceeded = true;
            continue;
        }
        if !exceeded {
            bytes.extend_from_slice(&chunk[..count]);
        }
    }
}

fn join_input(task: thread::JoinHandle<std::io::Result<()>>) -> Result<(), IngestionError> {
    task.join()
        .map_err(|_| IngestionError::OcrProcessFailed)?
        .map_err(|_| IngestionError::OcrProcessFailed)
}

fn join_output(
    task: thread::JoinHandle<Result<Vec<u8>, IngestionError>>,
) -> Result<Vec<u8>, IngestionError> {
    task.join().map_err(|_| IngestionError::OcrProcessFailed)?
}

#[derive(Debug)]
struct LineRegion {
    text: String,
    left: u32,
    top: u32,
    right: u32,
    bottom: u32,
    confidence_sum: u64,
    word_count: u64,
}

fn parse_tsv(
    imported: &ImportedImage,
    config: &TesseractConfig,
    bytes: &[u8],
) -> Result<OcrPage, IngestionError> {
    let text = std::str::from_utf8(bytes).map_err(|_| IngestionError::InvalidOcrOutput)?;
    let mut lines: BTreeMap<(u32, u32, u32, u32), LineRegion> = BTreeMap::new();
    for row in text.lines() {
        if row.starts_with("level\t") || row.trim().is_empty() {
            continue;
        }
        let fields = row.splitn(12, '\t').collect::<Vec<_>>();
        if fields.len() != 12 {
            return Err(IngestionError::InvalidOcrOutput);
        }
        let level = parse_u32(fields[0])?;
        if level != 5 {
            continue;
        }
        let page = parse_u32(fields[1])?;
        let block = parse_u32(fields[2])?;
        let paragraph = parse_u32(fields[3])?;
        let line = parse_u32(fields[4])?;
        let left = parse_u32(fields[6])?;
        let top = parse_u32(fields[7])?;
        let width = parse_u32(fields[8])?;
        let height = parse_u32(fields[9])?;
        let confidence = fields[10]
            .parse::<f32>()
            .map_err(|_| IngestionError::InvalidOcrOutput)?;
        let word = fields[11].trim();
        if word.is_empty() || confidence < 0.0 {
            continue;
        }
        if !confidence.is_finite() || confidence > 100.0 || width == 0 || height == 0 {
            return Err(IngestionError::InvalidOcrOutput);
        }
        let right = left
            .checked_add(width)
            .ok_or(IngestionError::InvalidOcrOutput)?;
        let bottom = top
            .checked_add(height)
            .ok_or(IngestionError::InvalidOcrOutput)?;
        let confidence_milli = (confidence * 10.0).round() as u64;
        lines
            .entry((page, block, paragraph, line))
            .and_modify(|region| {
                region.text.push(' ');
                region.text.push_str(word);
                region.left = region.left.min(left);
                region.top = region.top.min(top);
                region.right = region.right.max(right);
                region.bottom = region.bottom.max(bottom);
                region.confidence_sum += confidence_milli;
                region.word_count += 1;
            })
            .or_insert_with(|| LineRegion {
                text: word.to_owned(),
                left,
                top,
                right,
                bottom,
                confidence_sum: confidence_milli,
                word_count: 1,
            });
    }
    if lines.is_empty() {
        return Err(IngestionError::OcrNoText);
    }
    if lines.keys().any(|(page, _, _, _)| *page != 1) {
        return Err(IngestionError::InvalidOcrOutput);
    }
    let regions = lines
        .into_values()
        .map(|region| OcrRegion {
            text: region.text,
            x: region.left,
            y: region.top,
            width: region.right - region.left,
            height: region.bottom - region.top,
            confidence_milli: (region.confidence_sum / region.word_count) as u16,
        })
        .collect();
    let result = OcrPage {
        page: 1,
        width: imported.display_width,
        height: imported.display_height,
        engine: "tesseract".to_owned(),
        engine_version: config.engine_version.clone(),
        languages: config.languages.clone(),
        regions,
    };
    validate_ocr(imported, &result)?;
    Ok(result)
}

fn parse_u32(value: &str) -> Result<u32, IngestionError> {
    value.parse().map_err(|_| IngestionError::InvalidOcrOutput)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{import_image, ImageImportLimits};
    use image::{codecs::png::PngEncoder, ExtendedColorType, ImageEncoder};

    fn imported() -> ImportedImage {
        let pixels = vec![255u8; 100 * 40 * 3];
        let mut bytes = Vec::new();
        PngEncoder::new(&mut bytes)
            .write_image(&pixels, 100, 40, ExtendedColorType::Rgb8)
            .unwrap();
        import_image(
            &bytes,
            None,
            "2026-09-11T00:00:00Z".into(),
            ImageImportLimits::default(),
        )
        .unwrap()
    }

    fn config() -> TesseractConfig {
        TesseractConfig {
            executable: PathBuf::from("C:/not-used/tesseract.exe"),
            tessdata_dir: PathBuf::from("C:/not-used/tessdata"),
            engine_version: "5.5.0".into(),
            languages: vec!["vie".into(), "eng".into()],
            page_segmentation_mode: 6,
            timeout: Duration::from_secs(30),
            max_output_bytes: DEFAULT_MAX_OCR_OUTPUT_BYTES,
        }
    }

    #[test]
    fn tsv_words_are_grouped_into_bounded_lines_with_average_quality() {
        let tsv = concat!(
            "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n",
            "5\t1\t1\t1\t1\t1\t10\t5\t20\t10\t90.0\tBảo\n",
            "5\t1\t1\t1\t1\t2\t32\t5\t25\t10\t80.0\thành\n"
        );
        let result = parse_tsv(&imported(), &config(), tsv.as_bytes()).unwrap();
        assert_eq!(result.regions.len(), 1);
        assert_eq!(result.regions[0].text, "Bảo hành");
        assert_eq!(result.regions[0].confidence_milli, 850);
        assert_eq!((result.regions[0].x, result.regions[0].width), (10, 47));
    }

    #[test]
    fn malformed_empty_and_out_of_bounds_tsv_fail_closed() {
        assert_eq!(
            parse_tsv(&imported(), &config(), b"bad\trow"),
            Err(IngestionError::InvalidOcrOutput)
        );
        assert_eq!(
            parse_tsv(
                &imported(),
                &config(),
                b"level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n"
            ),
            Err(IngestionError::OcrNoText)
        );
        let outside = b"5\t1\t1\t1\t1\t1\t99\t0\t2\t1\t90\tbad\n";
        assert_eq!(
            parse_tsv(&imported(), &config(), outside),
            Err(IngestionError::OcrRegionOutOfBounds)
        );
    }

    #[test]
    fn invalid_worker_paths_are_rejected_before_spawn() {
        assert_eq!(
            run_tesseract(&imported(), &config()),
            Err(IngestionError::InvalidOcrConfiguration)
        );
    }

    #[test]
    fn output_reader_drains_but_rejects_bytes_over_limit() {
        assert_eq!(
            read_capped(std::io::Cursor::new(vec![7u8; 10_000]), 100),
            Err(IngestionError::OcrOutputTooLarge)
        );
    }
}
