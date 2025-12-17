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

// CLI Configuration
pub const Config = struct {
    command: []const u8 = "",
    data: []const u8 = "",
    input_file: ?[]const u8 = null,
    output_file: ?[]const u8 = null,
    format: OutputFormat = .PNG,
    error_level: ErrorCorrectionLevel = .M,
    size: u32 = 10,
    margin: u32 = 4,
    force_terminal: bool = false,
    raw_output: bool = false,
    image_files: std.ArrayList([]const u8),

    pub fn init() Config {
        return Config{
            .image_files = std.ArrayList([]const u8){},
        };
    }

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        for (self.image_files.items) |file| {
            allocator.free(file);
        }
        self.image_files.deinit(allocator);
        if (self.command.len > 0) allocator.free(self.command);
        if (self.input_file) |f| allocator.free(f);
        if (self.output_file) |f| allocator.free(f);
        if (self.data.len > 0) allocator.free(self.data);
    }
};

// QR Code Structure
pub const QRCode = struct {
    version: u8,
    size: u32,
    modules: []bool,
    is_function: []bool,
    ecc_level: ErrorCorrectionLevel,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, version: u8, ecc: ErrorCorrectionLevel) !QRCode {
        const size: u32 = @as(u32, version) * 4 + 17;
        const modules = try allocator.alloc(bool, size * size);
        const is_function = try allocator.alloc(bool, size * size);
        @memset(modules, false);
        @memset(is_function, false);

        return QRCode{
            .version = version,
            .size = size,
            .modules = modules,
            .is_function = is_function,
            .ecc_level = ecc,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *QRCode) void {
        self.allocator.free(self.modules);
        self.allocator.free(self.is_function);
    }

    pub fn getModule(self: *const QRCode, x: u32, y: u32) bool {
        if (x >= self.size or y >= self.size) return false;
        return self.modules[y * self.size + x];
    }

    pub fn setModule(self: *QRCode, x: u32, y: u32, value: bool) void {
        if (x >= self.size or y >= self.size) return;
        self.modules[y * self.size + x] = value;
    }

    pub fn isFunctionModule(self: *const QRCode, x: u32, y: u32) bool {
        if (x >= self.size or y >= self.size) return false;
        return self.is_function[y * self.size + x];
    }

    pub fn setFunctionModule(self: *QRCode, x: u32, y: u32, value: bool) void {
        if (x >= self.size or y >= self.size) return;
        const idx = y * self.size + x;
        self.modules[idx] = value;
        self.is_function[idx] = true;
    }
};


