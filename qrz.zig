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


