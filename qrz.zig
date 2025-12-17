const std = @import("std");

// QR Code Generator CLI Tool
// Supports generation with multiple output formats and QR code reading

const VERSION = "1.0.0";

// Error Correction Levels
pub const ErrorCorrectionLevel = enum(u8) {
    L = 0, // 7% recovery
    M = 1, // 15% recovery
    Q = 2, // 25% recovery
    H = 3, // 30% recovery

    pub fn fromString(s: []const u8) ?ErrorCorrectionLevel {
        if (std.ascii.eqlIgnoreCase(s, "L")) return .L;
        if (std.ascii.eqlIgnoreCase(s, "M")) return .M;
        if (std.ascii.eqlIgnoreCase(s, "Q")) return .Q;
        if (std.ascii.eqlIgnoreCase(s, "H")) return .H;
        return null;
    }
};

// QR Code Modes
pub const Mode = enum(u8) {
    Numeric = 1,
    Alphanumeric = 2,
    Byte = 4,
    Kanji = 8,
};

// Output Format
pub const OutputFormat = enum {
    PNG,
    TXT,
    ANSI,
    SVG,

    pub fn fromString(s: []const u8) ?OutputFormat {
        if (std.ascii.eqlIgnoreCase(s, "png")) return .PNG;
        if (std.ascii.eqlIgnoreCase(s, "txt")) return .TXT;
        if (std.ascii.eqlIgnoreCase(s, "ansi")) return .ANSI;
        if (std.ascii.eqlIgnoreCase(s, "svg")) return .SVG;
        return null;
    }
};


