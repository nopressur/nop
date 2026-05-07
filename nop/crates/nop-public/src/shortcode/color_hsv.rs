// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

//! HSV color space utilities for color manipulation
//!
//! This module provides functions to convert between RGB and HSV color spaces,
//! allowing for more precise color manipulation such as saturation adjustments.

/// Convert RGB color to HSV color space
///
/// # Arguments
/// * `r` - Red component (0-255)
/// * `g` - Green component (0-255)
/// * `b` - Blue component (0-255)
///
/// # Returns
/// * `(h, s, v)` - Hue (0-360), Saturation (0-1), Value (0-1)
pub fn rgb_to_hsv(r: u8, g: u8, b: u8) -> (f32, f32, f32) {
    let r = r as f32 / 255.0;
    let g = g as f32 / 255.0;
    let b = b as f32 / 255.0;

    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let delta = max - min;

    // Calculate hue
    let h = if delta == 0.0 {
        0.0
    } else if max == r {
        60.0 * (((g - b) / delta) % 6.0)
    } else if max == g {
        60.0 * (((b - r) / delta) + 2.0)
    } else {
        60.0 * (((r - g) / delta) + 4.0)
    };

    // Normalize hue to 0-360
    let h = if h < 0.0 { h + 360.0 } else { h };

    // Calculate saturation
    let s = if max == 0.0 { 0.0 } else { delta / max };

    // Value is just the max
    let v = max;

    (h, s, v)
}

/// Convert HSV color to RGB color space
///
/// # Arguments
/// * `h` - Hue (0-360)
/// * `s` - Saturation (0-1)
/// * `v` - Value (0-1)
///
/// # Returns
/// * `(r, g, b)` - Red, Green, Blue components (0-255)
pub fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (u8, u8, u8) {
    let c = v * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = v - c;

    let (r_prime, g_prime, b_prime) = if h < 60.0 {
        (c, x, 0.0)
    } else if h < 120.0 {
        (x, c, 0.0)
    } else if h < 180.0 {
        (0.0, c, x)
    } else if h < 240.0 {
        (0.0, x, c)
    } else if h < 300.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    let r = ((r_prime + m) * 255.0).round() as u8;
    let g = ((g_prime + m) * 255.0).round() as u8;
    let b = ((b_prime + m) * 255.0).round() as u8;

    (r, g, b)
}

/// Increase the saturation of an RGB color by a given factor
///
/// # Arguments
/// * `r` - Red component (0-255)
/// * `g` - Green component (0-255)
/// * `b` - Blue component (0-255)
/// * `factor` - Saturation multiplier (e.g., 1.3 for 30% increase)
///
/// # Returns
/// * `(r, g, b)` - RGB color with increased saturation
pub fn increase_saturation(r: u8, g: u8, b: u8, factor: f32) -> (u8, u8, u8) {
    let (h, s, v) = rgb_to_hsv(r, g, b);
    let new_s = (s * factor).min(1.0); // Clamp to maximum saturation of 1.0
    hsv_to_rgb(h, new_s, v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rgb_to_hsv_black() {
        let (h, s, v) = rgb_to_hsv(0, 0, 0);
        assert_eq!(h, 0.0);
        assert_eq!(s, 0.0);
        assert_eq!(v, 0.0);
    }

    #[test]
    fn test_rgb_to_hsv_white() {
        let (h, s, v) = rgb_to_hsv(255, 255, 255);
        assert_eq!(h, 0.0);
        assert_eq!(s, 0.0);
        assert_eq!(v, 1.0);
    }

    #[test]
    fn test_rgb_to_hsv_red() {
        let (h, s, v) = rgb_to_hsv(255, 0, 0);
        assert_eq!(h, 0.0);
        assert_eq!(s, 1.0);
        assert_eq!(v, 1.0);
    }

    #[test]
    fn test_rgb_to_hsv_green() {
        let (h, s, v) = rgb_to_hsv(0, 255, 0);
        assert_eq!(h, 120.0);
        assert_eq!(s, 1.0);
        assert_eq!(v, 1.0);
    }

    #[test]
    fn test_rgb_to_hsv_blue() {
        let (h, s, v) = rgb_to_hsv(0, 0, 255);
        assert_eq!(h, 240.0);
        assert_eq!(s, 1.0);
        assert_eq!(v, 1.0);
    }

    #[test]
    fn test_hsv_to_rgb_roundtrip() {
        let original = (128, 64, 192);
        let (h, s, v) = rgb_to_hsv(original.0, original.1, original.2);
        let result = hsv_to_rgb(h, s, v);

        // Allow for small rounding differences (within 1)
        assert!((result.0 as i16 - original.0 as i16).abs() <= 1);
        assert!((result.1 as i16 - original.1 as i16).abs() <= 1);
        assert!((result.2 as i16 - original.2 as i16).abs() <= 1);
    }

    #[test]
    fn test_increase_saturation() {
        // Test with a muted color (should become more vibrant)
        let (r, g, b) = increase_saturation(150, 120, 100, 1.3);

        // Should have increased saturation (more separation between components)
        let original_diff =
            (150i16 - 120i16).abs() + (150i16 - 100i16).abs() + (120i16 - 100i16).abs();
        let new_diff =
            (r as i16 - g as i16).abs() + (r as i16 - b as i16).abs() + (g as i16 - b as i16).abs();
        assert!(new_diff >= original_diff);
    }

    #[test]
    fn test_increase_saturation_already_saturated() {
        // Test with already saturated color (should clamp properly)
        let (r, g, b) = increase_saturation(255, 0, 0, 1.3);

        // Should remain valid and not change much (already fully saturated)
        assert_eq!(r, 255);
        assert_eq!(g, 0);
        assert_eq!(b, 0);
    }
}
