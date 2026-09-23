use crate::{hex_digest, IngestionError};
use foliora_domain::{
    Claim, ClaimStatus, Provenance, Sensitivity, Source, SourceLocator, SourceProvenance,
    ValidityWindow, SCHEMA_VERSION,
};
use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Cursor;

pub const DEFAULT_MAX_IMAGE_BYTES: usize = 25 * 1024 * 1024;
pub const DEFAULT_MAX_IMAGE_DIMENSION: u32 = 12_000;
pub const DEFAULT_MAX_IMAGE_PIXELS: u64 = 40_000_000;
pub const DEFAULT_MAX_IMAGE_DECODED_BYTES: u64 = 200 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageImportLimits {
    pub max_file_bytes: usize,
    pub max_dimension: u32,
    pub max_pixels: u64,
    pub max_decoded_bytes: u64,
}

impl Default for ImageImportLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_IMAGE_BYTES,
            max_dimension: DEFAULT_MAX_IMAGE_DIMENSION,
            max_pixels: DEFAULT_MAX_IMAGE_PIXELS,
            max_decoded_bytes: DEFAULT_MAX_IMAGE_DECODED_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedImageFormat {
    Png,
    Jpeg,
}

impl SupportedImageFormat {
    fn media_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageOrientation {
    Normal,
    Rotate90,
    Rotate180,
    Rotate270,
    FlipHorizontal,
    FlipVertical,
    Rotate90FlipHorizontal,
    Rotate270FlipHorizontal,
}

impl ImageOrientation {
    fn from_image(value: image::metadata::Orientation) -> Self {
        use image::metadata::Orientation;
        match value {
            Orientation::NoTransforms => Self::Normal,
            Orientation::Rotate90 => Self::Rotate90,
            Orientation::Rotate180 => Self::Rotate180,
            Orientation::Rotate270 => Self::Rotate270,
            Orientation::FlipHorizontal => Self::FlipHorizontal,
            Orientation::FlipVertical => Self::FlipVertical,
            Orientation::Rotate90FlipH => Self::Rotate90FlipHorizontal,
            Orientation::Rotate270FlipH => Self::Rotate270FlipHorizontal,
        }
    }

    fn swaps_axes(self) -> bool {
        matches!(
            self,
            Self::Rotate90
                | Self::Rotate270
                | Self::Rotate90FlipHorizontal
                | Self::Rotate270FlipHorizontal
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedImage {
    pub source: Source,
    pub format: SupportedImageFormat,
    pub encoded_width: u32,
    pub encoded_height: u32,
    pub display_width: u32,
    pub display_height: u32,
    pub orientation: ImageOrientation,
    pub decoded_bytes: u64,
    /// Orientation-applied PNG bytes intended only for the local OCR subprocess.
    pub ocr_input_png: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OcrRegion {
    pub text: String,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    /// Integer thousandths in the inclusive range 0..=1000.
    pub confidence_milli: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OcrPage {
    pub page: u32,
    pub width: u32,
    pub height: u32,
    pub engine: String,
    pub engine_version: String,
    pub languages: Vec<String>,
    pub regions: Vec<OcrRegion>,
}

/// Validates a PNG/JPEG and creates an orientation-applied in-memory OCR input.
pub fn import_image(
    bytes: &[u8],
    title: Option<String>,
    captured_at: String,
    limits: ImageImportLimits,
) -> Result<ImportedImage, IngestionError> {
    validate_limits(limits)?;
    if bytes.is_empty() {
        return Err(IngestionError::Empty);
    }
    if bytes.len() > limits.max_file_bytes {
        return Err(IngestionError::TooLarge {
            actual: bytes.len(),
            limit: limits.max_file_bytes,
        });
    }

    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| IngestionError::InvalidImage)?;
    let format = match reader.format() {
        Some(ImageFormat::Png) => SupportedImageFormat::Png,
        Some(ImageFormat::Jpeg) => SupportedImageFormat::Jpeg,
        Some(_) | None => return Err(IngestionError::UnsupportedImageFormat),
    };
    let mut decoder_limits = Limits::default();
    decoder_limits.max_image_width = Some(limits.max_dimension);
    decoder_limits.max_image_height = Some(limits.max_dimension);
    decoder_limits.max_alloc = Some(limits.max_decoded_bytes);
    let mut decoder = reader
        .into_decoder()
        .map_err(|_| IngestionError::InvalidImage)?;
    let (width, height) = decoder.dimensions();
    if width == 0 || height == 0 {
        return Err(IngestionError::InvalidImage);
    }
    if width > limits.max_dimension || height > limits.max_dimension {
        return Err(IngestionError::ImageDimensionsExceeded {
            width,
            height,
            max_dimension: limits.max_dimension,
        });
    }
    let pixels = u64::from(width).checked_mul(u64::from(height)).ok_or(
        IngestionError::ImagePixelsExceeded {
            actual: u64::MAX,
            limit: limits.max_pixels,
        },
    )?;
    if pixels > limits.max_pixels {
        return Err(IngestionError::ImagePixelsExceeded {
            actual: pixels,
            limit: limits.max_pixels,
        });
    }
    let decoded_bytes = decoder.total_bytes();
    if decoded_bytes > limits.max_decoded_bytes {
        return Err(IngestionError::ImageDecodedTooLarge {
            actual: decoded_bytes,
            limit: limits.max_decoded_bytes,
        });
    }
    decoder
        .set_limits(decoder_limits)
        .map_err(|_| IngestionError::InvalidImage)?;
    let raw_orientation = decoder
        .orientation()
        .map_err(|_| IngestionError::InvalidImage)?;
    let orientation = ImageOrientation::from_image(raw_orientation);
    // `total_bytes` was checked before this allocation. This avoids relying on
    // the decoder's non-strict allocation limit as the only memory boundary.
    let mut decoded =
        DynamicImage::from_decoder(decoder).map_err(|_| IngestionError::InvalidImage)?;
    decoded.apply_orientation(raw_orientation);
    let mut ocr_input = Cursor::new(Vec::new());
    decoded
        .write_to(&mut ocr_input, ImageFormat::Png)
        .map_err(|_| IngestionError::InvalidImage)?;
    let ocr_input_png = ocr_input.into_inner();
    if ocr_input_png.len() as u64 > limits.max_decoded_bytes {
        return Err(IngestionError::ImageDecodedTooLarge {
            actual: ocr_input_png.len() as u64,
            limit: limits.max_decoded_bytes,
        });
    }

    let fingerprint = format!("sha256:{}", hex_digest(bytes));
    let mut source = Source::new(
        format!("source:{}", &fingerprint[7..]),
        fingerprint,
        format.media_type().to_owned(),
        captured_at,
    )?;
    source.title = title.filter(|value| !value.trim().is_empty());
    source.validate()?;
    let (display_width, display_height) = if orientation.swaps_axes() {
        (height, width)
    } else {
        (width, height)
    };
    Ok(ImportedImage {
        source,
        format,
        encoded_width: width,
        encoded_height: height,
        display_width,
        display_height,
        orientation,
        decoded_bytes,
        ocr_input_png,
    })
}

/// Converts one validated OCR region into a review-required candidate claim.
pub fn candidate_from_ocr_region(
    imported: &ImportedImage,
    ocr: &OcrPage,
    region_index: usize,
    claim_type: String,
    subject: String,
) -> Result<Claim, IngestionError> {
    validate_ocr(imported, ocr)?;
    let region = ocr
        .regions
        .get(region_index)
        .ok_or(IngestionError::InvalidOcrResult)?;
    validate_region(region, ocr.width, ocr.height)?;
    let identity = format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        imported.source.id,
        claim_type,
        subject,
        region.x,
        region.y,
        region.width,
        region.height,
        region.text
    );
    let languages = ocr.languages.join("+");
    let claim = Claim {
        schema_version: SCHEMA_VERSION,
        id: format!("claim:{}", hex_digest(identity.as_bytes())),
        claim_type,
        subject,
        value: Value::String(region.text.clone()),
        status: ClaimStatus::Candidate,
        provenance: Provenance::Source(SourceProvenance {
            source_id: imported.source.id.clone(),
            locator: SourceLocator::Region {
                page: ocr.page,
                x: region.x,
                y: region.y,
                width: region.width,
                height: region.height,
            },
            extractor: Some(format!(
                "foliora:ocr:{}:{}:{}:confidence={}",
                ocr.engine, ocr.engine_version, languages, region.confidence_milli
            )),
        }),
        captured_at: imported.source.captured_at.clone(),
        validity: ValidityWindow::default(),
        sensitivity: Sensitivity::Private,
        revision: 0,
    };
    claim.validate()?;
    Ok(claim)
}

pub(crate) fn validate_ocr(imported: &ImportedImage, ocr: &OcrPage) -> Result<(), IngestionError> {
    if ocr.page != 1
        || ocr.width != imported.display_width
        || ocr.height != imported.display_height
        || !valid_identifier(&ocr.engine)
        || !valid_identifier(&ocr.engine_version)
        || ocr.languages.is_empty()
        || ocr
            .languages
            .iter()
            .any(|language| !valid_identifier(language))
    {
        return Err(IngestionError::InvalidOcrResult);
    }
    for region in &ocr.regions {
        validate_region(region, ocr.width, ocr.height)?;
    }
    Ok(())
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_region(region: &OcrRegion, width: u32, height: u32) -> Result<(), IngestionError> {
    if region.text.trim().is_empty() || region.width == 0 || region.height == 0 {
        return Err(IngestionError::OcrRegionEmpty);
    }
    if region.confidence_milli > 1_000 {
        return Err(IngestionError::OcrConfidenceOutOfRange);
    }
    let right = region
        .x
        .checked_add(region.width)
        .ok_or(IngestionError::OcrRegionOutOfBounds)?;
    let bottom = region
        .y
        .checked_add(region.height)
        .ok_or(IngestionError::OcrRegionOutOfBounds)?;
    if right > width || bottom > height {
        return Err(IngestionError::OcrRegionOutOfBounds);
    }
    Ok(())
}

fn validate_limits(limits: ImageImportLimits) -> Result<(), IngestionError> {
    if limits.max_file_bytes == 0
        || limits.max_dimension == 0
        || limits.max_pixels == 0
        || limits.max_decoded_bytes == 0
    {
        return Err(IngestionError::InvalidImageLimits);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{
        codecs::jpeg::JpegEncoder, codecs::png::PngEncoder, ExtendedColorType, ImageEncoder,
    };

    const CAPTURED: &str = "2026-09-11T00:00:00Z";

    fn png(width: u32, height: u32) -> Vec<u8> {
        let pixels = vec![255u8; (width * height * 3) as usize];
        let mut bytes = Vec::new();
        PngEncoder::new(&mut bytes)
            .write_image(&pixels, width, height, ExtendedColorType::Rgb8)
            .unwrap();
        bytes
    }

    fn jpeg(width: u32, height: u32) -> Vec<u8> {
        let pixels = vec![192u8; (width * height * 3) as usize];
        let mut bytes = Vec::new();
        JpegEncoder::new_with_quality(&mut bytes, 90)
            .write_image(&pixels, width, height, ExtendedColorType::Rgb8)
            .unwrap();
        bytes
    }

    fn imported() -> ImportedImage {
        import_image(
            &png(4, 3),
            Some("scan.png".into()),
            CAPTURED.into(),
            ImageImportLimits::default(),
        )
        .unwrap()
    }

    fn ocr(region: OcrRegion) -> OcrPage {
        OcrPage {
            page: 1,
            width: 4,
            height: 3,
            engine: "tesseract".into(),
            engine_version: "5.x".into(),
            languages: vec!["vie".into(), "eng".into()],
            regions: vec![region],
        }
    }

    #[test]
    fn valid_png_is_fingerprinted_and_fully_decoded() {
        let bytes = png(4, 3);
        let image = import_image(
            &bytes,
            Some("scan.png".into()),
            CAPTURED.into(),
            ImageImportLimits::default(),
        )
        .unwrap();
        assert_eq!(image.format, SupportedImageFormat::Png);
        assert_eq!((image.display_width, image.display_height), (4, 3));
        assert_eq!(image.decoded_bytes, 36);
        assert!(image.ocr_input_png.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert_eq!(
            image.source.fingerprint,
            format!("sha256:{}", hex_digest(&bytes))
        );
    }

    #[test]
    fn valid_jpeg_is_detected_from_bytes_not_filename() {
        let image = import_image(
            &jpeg(3, 2),
            Some("misleading.png".into()),
            CAPTURED.into(),
            ImageImportLimits::default(),
        )
        .unwrap();
        assert_eq!(image.format, SupportedImageFormat::Jpeg);
        assert_eq!(image.source.media_type, "image/jpeg");
        assert_eq!((image.encoded_width, image.encoded_height), (3, 2));
    }

    #[test]
    fn corrupt_unsupported_and_oversized_images_fail_closed() {
        assert_eq!(
            import_image(
                b"not-image",
                None,
                CAPTURED.into(),
                ImageImportLimits::default()
            ),
            Err(IngestionError::UnsupportedImageFormat)
        );
        let limits = ImageImportLimits {
            max_dimension: 1,
            ..ImageImportLimits::default()
        };
        assert!(matches!(
            import_image(&png(2, 2), None, CAPTURED.into(), limits),
            Err(IngestionError::ImageDimensionsExceeded { .. })
        ));
        let limits = ImageImportLimits {
            max_pixels: 3,
            ..ImageImportLimits::default()
        };
        assert!(matches!(
            import_image(&png(2, 2), None, CAPTURED.into(), limits),
            Err(IngestionError::ImagePixelsExceeded { .. })
        ));
    }

    #[test]
    fn ocr_region_creates_candidate_with_region_and_quality() {
        let image = imported();
        let result = ocr(OcrRegion {
            text: "Mã BH-123".into(),
            x: 0,
            y: 0,
            width: 4,
            height: 2,
            confidence_milli: 912,
        });
        let claim = candidate_from_ocr_region(
            &image,
            &result,
            0,
            "warranty.code".into(),
            "device:1".into(),
        )
        .unwrap();
        assert_eq!(claim.status, ClaimStatus::Candidate);
        assert!(matches!(
            claim.provenance,
            Provenance::Source(SourceProvenance {
                locator: SourceLocator::Region { page: 1, .. },
                extractor: Some(ref value),
                ..
            }) if value.contains("vie+eng") && value.contains("confidence=912")
        ));
    }

    #[test]
    fn invalid_ocr_bounds_quality_and_dimensions_are_rejected() {
        let image = imported();
        let bad_bounds = ocr(OcrRegion {
            text: "outside".into(),
            x: 3,
            y: 0,
            width: 2,
            height: 1,
            confidence_milli: 500,
        });
        assert_eq!(
            candidate_from_ocr_region(&image, &bad_bounds, 0, "x".into(), "y".into()),
            Err(IngestionError::OcrRegionOutOfBounds)
        );
        let bad_quality = ocr(OcrRegion {
            text: "quality".into(),
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            confidence_milli: 1_001,
        });
        assert_eq!(
            candidate_from_ocr_region(&image, &bad_quality, 0, "x".into(), "y".into()),
            Err(IngestionError::OcrConfidenceOutOfRange)
        );
        let mut mismatched = ocr(OcrRegion {
            text: "text".into(),
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            confidence_milli: 500,
        });
        mismatched.width = 99;
        assert_eq!(
            candidate_from_ocr_region(&image, &mismatched, 0, "x".into(), "y".into()),
            Err(IngestionError::InvalidOcrResult)
        );
        mismatched.width = image.display_width;
        mismatched.engine = "bad:engine".into();
        assert_eq!(
            candidate_from_ocr_region(&image, &mismatched, 0, "x".into(), "y".into()),
            Err(IngestionError::InvalidOcrResult)
        );
    }
}
