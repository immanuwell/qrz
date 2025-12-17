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

// Galois Field arithmetic for Reed-Solomon
pub const GaloisField = struct {
    const FIELD_SIZE = 256;
    const PRIMITIVE = 0x11D; // x^8 + x^4 + x^3 + x^2 + 1

    var exp_table: [FIELD_SIZE]u8 = undefined;
    var log_table: [FIELD_SIZE]u8 = undefined;
    var initialized = false;

    pub fn init() void {
        if (initialized) return;

        var x: u32 = 1;
        for (0..FIELD_SIZE) |i| {
            exp_table[i] = @intCast(x);
            log_table[x] = @intCast(i);
            x = x << 1;
            if (x >= FIELD_SIZE) {
                x ^= PRIMITIVE;
            }
        }
        initialized = true;
    }

    pub fn multiply(a: u8, b: u8) u8 {
        if (a == 0 or b == 0) return 0;
        const log_a: u32 = log_table[a];
        const log_b: u32 = log_table[b];
        return exp_table[(log_a + log_b) % 255];
    }

    pub fn exp(x: u8) u8 {
        return exp_table[x];
    }

    pub fn log(x: u8) u8 {
        return log_table[x];
    }
};

// Reed-Solomon Error Correction
pub const ReedSolomon = struct {
    pub fn generatePolynomial(allocator: std.mem.Allocator, degree: u32) ![]u8 {
        var poly = try allocator.alloc(u8, degree + 1);
        @memset(poly, 0);
        poly[0] = 1;

        for (0..degree) |i| {
            const factor = GaloisField.exp(@intCast(i));
            for (0..i + 1) |j| {
                const idx = i - j;
                poly[idx + 1] ^= GaloisField.multiply(poly[idx], factor);
            }
        }

        return poly;
    }

    pub fn encode(allocator: std.mem.Allocator, data: []const u8, ecc_count: u32) ![]u8 {
        GaloisField.init();

        const generator = try generatePolynomial(allocator, ecc_count);
        defer allocator.free(generator);

        var result = try allocator.alloc(u8, data.len + ecc_count);
        @memcpy(result[0..data.len], data);
        @memset(result[data.len..], 0);

        for (0..data.len) |i| {
            const coef = result[i];
            if (coef != 0) {
                for (0..generator.len) |j| {
                    result[i + j] ^= GaloisField.multiply(generator[j], coef);
                }
            }
        }

        // Copy just the ECC bytes to a new allocation
        const ecc_bytes = try allocator.alloc(u8, ecc_count);
        @memcpy(ecc_bytes, result[data.len..]);
        allocator.free(result);

        return ecc_bytes;
    }
};

// QR Code Encoder
pub const QREncoder = struct {
    const MAX_VERSION: u8 = 6; // Keep tables small + correct; extend with full spec tables if needed.

    fn absI32(x: i32) i32 {
        return if (x < 0) -x else x;
    }

    pub fn encode(allocator: std.mem.Allocator, data: []const u8, ecc: ErrorCorrectionLevel) !QRCode {
        GaloisField.init();

        const mode = detectMode(data);
        const version = try selectVersion(allocator, data, mode, ecc);
        var qr = try QRCode.init(allocator, version, ecc);
        errdefer qr.deinit();

        drawFunctionPatterns(&qr);

        const data_codewords = try encodeDataCodewords(allocator, data, mode, version, ecc);
        defer allocator.free(data_codewords);

        const all_codewords = try addErrorCorrectionAndInterleave(allocator, data_codewords, version, ecc);
        defer allocator.free(all_codewords);

        drawCodewords(&qr, all_codewords);

        const mask = chooseBestMask(&qr, ecc);
        applyMask(&qr, mask);
        drawFormatBits(&qr, ecc, mask);
        if (version >= 7) drawVersionBits(&qr);

        return qr;
    }

    fn selectVersion(allocator: std.mem.Allocator, data: []const u8, mode: Mode, ecc: ErrorCorrectionLevel) !u8 {
        var bits = std.ArrayList(u8){};
        defer bits.deinit(allocator);

        // Build the payload bitstream once (without final padding) so we can test sizes.
        try appendBits(allocator, &bits, @intFromEnum(mode), 4);
        // Char count length depends on version; handled per-version below.
        const data_bits = bits.items;
        _ = data_bits;

        for (1..MAX_VERSION + 1) |v_usize| {
            const version: u8 = @intCast(v_usize);
            bits.items.len = 0;

            try appendBits(allocator, &bits, @intFromEnum(mode), 4);
            const count_bits = getCharCountBits(mode, version);
            try appendBits(allocator, &bits, @intCast(data.len), count_bits);

            switch (mode) {
                .Numeric => try encodeNumeric(allocator, &bits, data),
                .Alphanumeric => try encodeAlphanumeric(allocator, &bits, data),
                .Byte => try encodeByte(allocator, &bits, data),
                .Kanji => return error.KanjiNotSupported,
            }

            const capacity_bits: usize = getNumDataCodewords(version, ecc) * 8;
            if (bits.items.len <= capacity_bits) return version;
        }

        return error.DataTooLarge;
    }

    fn detectMode(data: []const u8) Mode {
        var is_numeric = true;
        var is_alpha = true;

        for (data) |byte| {
            if (byte < '0' or byte > '9') {
                is_numeric = false;
            }
            if (!isAlphanumeric(byte)) {
                is_alpha = false;
            }
        }

        if (is_numeric) return .Numeric;
        if (is_alpha) return .Alphanumeric;
        return .Byte;
    }

    fn isAlphanumeric(c: u8) bool {
        return (c >= '0' and c <= '9') or
               (c >= 'A' and c <= 'Z') or
               c == ' ' or c == '$' or c == '%' or c == '*' or
               c == '+' or c == '-' or c == '.' or c == '/' or c == ':';
    }

    fn encodeDataCodewords(allocator: std.mem.Allocator, data: []const u8, mode: Mode, version: u8, ecc: ErrorCorrectionLevel) ![]u8 {
        var bits = std.ArrayList(u8){};
        defer bits.deinit(allocator);

        // Add mode indicator (4 bits)
        try appendBits(allocator, &bits, @intFromEnum(mode), 4);

        // Add character count indicator
        const count_bits = getCharCountBits(mode, version);
        try appendBits(allocator, &bits, @intCast(data.len), count_bits);

        // Encode data based on mode
        switch (mode) {
            .Numeric => try encodeNumeric(allocator, &bits, data),
            .Alphanumeric => try encodeAlphanumeric(allocator, &bits, data),
            .Byte => try encodeByte(allocator, &bits, data),
            .Kanji => return error.KanjiNotSupported,
        }

        // Add terminator (up to 4 zero bits)
        const capacity: usize = getNumDataCodewords(version, ecc);
        const bit_capacity: usize = capacity * 8;
        const terminator_len: usize = if (bits.items.len < bit_capacity) @min(4, bit_capacity - bits.items.len) else 0;
        for (0..terminator_len) |_| {
            try bits.append(allocator, 0);
        }

        // Pad to byte boundary
        while (bits.items.len % 8 != 0) {
            try bits.append(allocator, 0);
        }

        // Convert bits to bytes
        var result = try allocator.alloc(u8, bits.items.len / 8);
        for (0..result.len) |i| {
            var byte: u8 = 0;
            for (0..8) |j| {
                byte = (byte << 1) | bits.items[i * 8 + j];
            }
            result[i] = byte;
        }

        // Add padding bytes
        const needed: usize = capacity;
        if (result.len < needed) {
            const old_result = result;
            result = try allocator.alloc(u8, needed);
            @memcpy(result[0..old_result.len], old_result);
            allocator.free(old_result);

            var pad_idx: usize = old_result.len;
            var pad_pattern: u8 = 0xEC;
            while (pad_idx < needed) : (pad_idx += 1) {
                result[pad_idx] = pad_pattern;
                pad_pattern = if (pad_pattern == 0xEC) 0x11 else 0xEC;
            }
        }

        return result;
    }

    fn appendBits(allocator: std.mem.Allocator, bits: *std.ArrayList(u8), value: u32, count: u32) !void {
        var i: u32 = count;
        while (i > 0) {
            i -= 1;
            const bit: u8 = if ((value >> @intCast(i)) & 1 == 1) 1 else 0;
            try bits.append(allocator, bit);
        }
    }

    fn encodeNumeric(allocator: std.mem.Allocator, bits: *std.ArrayList(u8), data: []const u8) !void {
        var i: usize = 0;
        while (i < data.len) {
            const chunk_len = @min(3, data.len - i);
            var value: u32 = 0;
            for (0..chunk_len) |j| {
                value = value * 10 + (data[i + j] - '0');
            }
            const bit_count: u32 = if (chunk_len == 3) 10 else if (chunk_len == 2) 7 else 4;
            try appendBits(allocator, bits, value, bit_count);
            i += chunk_len;
        }
    }

    fn encodeAlphanumeric(allocator: std.mem.Allocator, bits: *std.ArrayList(u8), data: []const u8) !void {
        const ALPHANUMERIC_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

        var i: usize = 0;
        while (i < data.len) {
            const val1 = std.mem.indexOfScalar(u8, ALPHANUMERIC_CHARSET, data[i]) orelse 0;
            if (i + 1 < data.len) {
                const val2 = std.mem.indexOfScalar(u8, ALPHANUMERIC_CHARSET, data[i + 1]) orelse 0;
                try appendBits(allocator, bits, @intCast(val1 * 45 + val2), 11);
                i += 2;
            } else {
                try appendBits(allocator, bits, @intCast(val1), 6);
                i += 1;
            }
        }
    }

    fn encodeByte(allocator: std.mem.Allocator, bits: *std.ArrayList(u8), data: []const u8) !void {
        for (data) |byte| {
            try appendBits(allocator, bits, byte, 8);
        }
    }

    fn getCharCountBits(mode: Mode, version: u8) u32 {
        return switch (mode) {
            .Numeric => if (version < 10) 10 else if (version < 27) 12 else 14,
            .Alphanumeric => if (version < 10) 9 else if (version < 27) 11 else 13,
            .Byte => if (version < 10) 8 else 16,
            .Kanji => if (version < 10) 8 else if (version < 27) 10 else 12,
        };
    }

    fn getECCCodewordsPerBlock(ecc: ErrorCorrectionLevel, version: u8) u8 {
        if (version < 1 or version > MAX_VERSION) return 0;
        const table = [_][7]u8{
            // L
            [_]u8{ 0, 7, 10, 15, 20, 26, 18 },
            // M
            [_]u8{ 0, 10, 16, 26, 18, 24, 16 },
            // Q
            [_]u8{ 0, 13, 22, 18, 26, 18, 24 },
            // H
            [_]u8{ 0, 17, 28, 22, 16, 22, 28 },
        };
        return table[@intFromEnum(ecc)][version];
    }

    fn getNumErrorCorrectionBlocks(ecc: ErrorCorrectionLevel, version: u8) u8 {
        if (version < 1 or version > MAX_VERSION) return 0;
        const table = [_][7]u8{
            // L
            [_]u8{ 0, 1, 1, 1, 1, 1, 2 },
            // M
            [_]u8{ 0, 1, 1, 1, 2, 2, 4 },
            // Q
            [_]u8{ 0, 1, 1, 2, 2, 4, 4 },
            // H
            [_]u8{ 0, 1, 1, 2, 4, 4, 4 },
        };
        return table[@intFromEnum(ecc)][version];
    }

    fn getNumRawDataModules(version: u8) u32 {
        const v: u32 = version;
        var result: u32 = (16 * v + 128) * v + 64;
        if (version >= 2) {
            const num_align: u32 = v / 7 + 2;
            result -= (25 * num_align - 10) * num_align - 55;
            if (version >= 7) result -= 36;
        }
        return result;
    }

    fn getNumDataCodewords(version: u8, ecc: ErrorCorrectionLevel) usize {
        if (version < 1 or version > MAX_VERSION) return 0;
        const total_codewords: u32 = getNumRawDataModules(version) / 8;
        const ecc_per_block: u32 = getECCCodewordsPerBlock(ecc, version);
        const num_blocks: u32 = getNumErrorCorrectionBlocks(ecc, version);
        return @intCast(total_codewords - ecc_per_block * num_blocks);
    }

    fn getAlignmentPatternPositions(version: u8, out: *[7]u8) []const u8 {
        if (version == 1) return &[_]u8{};
        const size: u8 = version * 4 + 17;
        const num_align: u8 = version / 7 + 2;
        out[0] = 6;
        out[num_align - 1] = size - 7;
        if (num_align > 2) {
            var step: u8 = @intCast((size - 13) / (num_align - 1));
            if (step % 2 == 1) step += 1;
            var pos: u8 = size - 7 - step;
            var i: i32 = @intCast(num_align - 2);
            while (i >= 1) : (i -= 1) {
                out[@intCast(i)] = pos;
                pos -= step;
            }
        }
        return out[0..num_align];
    }

    fn drawFunctionPatterns(qr: *QRCode) void {
        // Finder patterns + separators (included in the 9x9 drawing)
        drawFinderPattern(qr, 3, 3);
        drawFinderPattern(qr, @intCast(qr.size - 4), 3);
        drawFinderPattern(qr, 3, @intCast(qr.size - 4));

        // Timing patterns
        for (8..qr.size - 8) |i| {
            const color = (i % 2) == 0;
            qr.setFunctionModule(@intCast(i), 6, color);
            qr.setFunctionModule(6, @intCast(i), color);
        }

        // Alignment patterns
        var pos_buf: [7]u8 = undefined;
        const positions = getAlignmentPatternPositions(qr.version, &pos_buf);
        for (positions) |y| {
            for (positions) |x| {
                // Skip the three finder corners
                if ((x == 6 and y == 6) or
                    (x == 6 and y == qr.size - 7) or
                    (x == qr.size - 7 and y == 6))
                {
                    continue;
                }
                drawAlignmentPattern(qr, x, y);
            }
        }

        // Dark module
        qr.setFunctionModule(8, @intCast(qr.size - 8), true);

        // Reserve format information areas (set to light; overwritten later)
        for (0..6) |i| qr.setFunctionModule(8, @intCast(i), false);
        qr.setFunctionModule(8, 7, false);
        qr.setFunctionModule(8, 8, false);
        qr.setFunctionModule(7, 8, false);
        for (0..6) |i| qr.setFunctionModule(@intCast(i), 8, false);
        for (0..8) |i| qr.setFunctionModule(@intCast(qr.size - 1 - i), 8, false);
        for (0..7) |i| qr.setFunctionModule(8, @intCast(qr.size - 1 - i), false);

        // Reserve version info
        if (qr.version >= 7) {
            for (0..6) |i| {
                for (0..3) |j| {
                    const x: u32 = @intCast(i);
                    const y: u32 = @intCast(j);
                    qr.setFunctionModule(qr.size - 11 + x, y, false);
                    qr.setFunctionModule(y, qr.size - 11 + x, false);
                }
            }
        }
    }

    fn drawFinderPattern(qr: *QRCode, x: u32, y: u32) void {
        const cx: i32 = @intCast(x);
        const cy: i32 = @intCast(y);
        for (0..9) |dy_usize| {
            for (0..9) |dx_usize| {
                const dx: i32 = @as(i32, @intCast(dx_usize)) - 4;
                const dy: i32 = @as(i32, @intCast(dy_usize)) - 4;
                const dist: i32 = @max(absI32(dx), absI32(dy));
                const color = dist != 2 and dist != 4;
                const xx: i32 = cx + dx;
                const yy: i32 = cy + dy;
                if (xx >= 0 and yy >= 0 and xx < @as(i32, @intCast(qr.size)) and yy < @as(i32, @intCast(qr.size))) {
                    qr.setFunctionModule(@intCast(xx), @intCast(yy), color);
                }
            }
        }
    }

    fn drawAlignmentPattern(qr: *QRCode, x: u8, y: u8) void {
        const cx: u32 = x;
        const cy: u32 = y;
        for (0..5) |dy| {
            for (0..5) |dx| {
                const dist_x: i32 = absI32(@as(i32, @intCast(dx)) - 2);
                const dist_y: i32 = absI32(@as(i32, @intCast(dy)) - 2);
                const dist: i32 = @max(dist_x, dist_y);
                const color = dist != 1;
                qr.setFunctionModule(cx + @as(u32, @intCast(dx)) - 2, cy + @as(u32, @intCast(dy)) - 2, color);
            }
        }
    }

    fn addErrorCorrectionAndInterleave(allocator: std.mem.Allocator, data: []const u8, version: u8, ecc: ErrorCorrectionLevel) ![]u8 {
        const num_blocks: usize = getNumErrorCorrectionBlocks(ecc, version);
        const ecc_len: usize = getECCCodewordsPerBlock(ecc, version);
        const total_codewords: usize = @intCast(getNumRawDataModules(version) / 8);
        const data_len: usize = data.len;

        const short_block_len: usize = data_len / num_blocks;
        const num_long_blocks: usize = data_len % num_blocks;
        const num_short_blocks: usize = num_blocks - num_long_blocks;
        const long_block_len: usize = short_block_len + 1;

        var blocks = try allocator.alloc([]const u8, num_blocks);
        defer allocator.free(blocks);
        var ecc_blocks = try allocator.alloc([]u8, num_blocks);
        defer allocator.free(ecc_blocks);

        var offset: usize = 0;
        var filled: usize = 0;
        errdefer {
            for (0..filled) |i| allocator.free(ecc_blocks[i]);
        }
        for (0..num_blocks) |b| {
            const is_long = b >= num_short_blocks;
            const block_len = if (is_long) long_block_len else short_block_len;
            const slice = data[offset .. offset + block_len];
            offset += block_len;
            blocks[b] = slice;
            ecc_blocks[b] = try reedSolomonComputeRemainder(allocator, slice, ecc_len);
            filled += 1;
        }
        defer {
            for (ecc_blocks) |blk| allocator.free(blk);
        }

        var result = try allocator.alloc(u8, total_codewords);
        var out_idx: usize = 0;

        // Interleave data bytes
        for (0..long_block_len) |i| {
            for (0..num_blocks) |b| {
                const blk = blocks[b];
                if (i < blk.len) {
                    result[out_idx] = blk[i];
                    out_idx += 1;
                }
            }
        }

        // Interleave ECC bytes (all blocks same ecc_len)
        for (0..ecc_len) |i| {
            for (0..num_blocks) |b| {
                result[out_idx] = ecc_blocks[b][i];
                out_idx += 1;
            }
        }

        std.debug.assert(out_idx == total_codewords);
        return result;
    }

    fn reedSolomonComputeDivisor(allocator: std.mem.Allocator, degree: usize) ![]u8 {
        var result = try allocator.alloc(u8, degree);
        @memset(result, 0);
        result[degree - 1] = 1;
        var root: u8 = 1;
        for (0..degree) |_| {
            for (0..degree) |i| {
                result[i] = GaloisField.multiply(result[i], root);
                if (i + 1 < degree) result[i] ^= result[i + 1];
            }
            root = GaloisField.multiply(root, 0x02);
        }
        return result;
    }

    fn reedSolomonComputeRemainder(allocator: std.mem.Allocator, data: []const u8, degree: usize) ![]u8 {
        const divisor = try reedSolomonComputeDivisor(allocator, degree);
        defer allocator.free(divisor);

        var result = try allocator.alloc(u8, degree);
        @memset(result, 0);

        for (data) |b| {
            const factor = b ^ result[0];
            std.mem.copyForwards(u8, result[0 .. degree - 1], result[1..degree]);
            result[degree - 1] = 0;
            for (0..degree) |i| {
                result[i] ^= GaloisField.multiply(divisor[i], factor);
            }
        }
        return result;
    }

    fn drawCodewords(qr: *QRCode, codewords: []const u8) void {
        var bit_idx: usize = 0;
        const total_bits: usize = codewords.len * 8;

        var right: i32 = @intCast(qr.size - 1);
        var y: i32 = @intCast(qr.size - 1);
        var upward = true;

        while (right > 0) : (right -= 2) {
            if (right == 6) right -= 1;
            while (true) {
                for (0..2) |dx| {
                    const x: u32 = @intCast(right - @as(i32, @intCast(dx)));
                    const yy: u32 = @intCast(y);
                    if (!qr.isFunctionModule(x, yy)) {
                        const bit: bool = if (bit_idx < total_bits)
                            (((codewords[bit_idx / 8] >> @intCast(7 - (bit_idx % 8))) & 1) == 1)
                        else
                            false;
                        qr.setModule(x, yy, bit);
                        bit_idx += 1;
                    }
                }
                if (upward) {
                    if (y == 0) break;
                    y -= 1;
                } else {
                    if (y == @as(i32, @intCast(qr.size - 1))) break;
                    y += 1;
                }
            }
            upward = !upward;
        }
    }

    fn maskBit(mask: u8, x: u32, y: u32) bool {
        return switch (mask) {
            0 => ((x + y) % 2) == 0,
            1 => (y % 2) == 0,
            2 => (x % 3) == 0,
            3 => ((x + y) % 3) == 0,
            4 => (((x / 3) + (y / 2)) % 2) == 0,
            5 => ((x * y) % 2 + (x * y) % 3) == 0,
            6 => ((((x * y) % 2) + ((x * y) % 3)) % 2) == 0,
            7 => ((((x + y) % 2) + ((x * y) % 3)) % 2) == 0,
            else => false,
        };
    }

    fn applyMask(qr: *QRCode, mask: u8) void {
        for (0..qr.size) |y| {
            for (0..qr.size) |x| {
                const ux: u32 = @intCast(x);
                const uy: u32 = @intCast(y);
                if (!qr.isFunctionModule(ux, uy) and maskBit(mask, ux, uy)) {
                    qr.setModule(ux, uy, !qr.getModule(ux, uy));
                }
            }
        }
    }

    fn chooseBestMask(qr: *QRCode, ecc: ErrorCorrectionLevel) u8 {
        var best_mask: u8 = 0;
        var best_score: i32 = std.math.maxInt(i32);

        const saved = qr.allocator.alloc(bool, qr.modules.len) catch return 0;
        defer qr.allocator.free(saved);
        @memcpy(saved, qr.modules);

        for (0..8) |mask_usize| {
            const mask: u8 = @intCast(mask_usize);
            @memcpy(qr.modules, saved);
            applyMask(qr, mask);
            drawFormatBits(qr, ecc, mask);
            const score = getPenaltyScore(qr);
            if (score < best_score) {
                best_score = score;
                best_mask = mask;
            }
        }

        @memcpy(qr.modules, saved);
        return best_mask;
    }

    fn getPenaltyScore(qr: *const QRCode) i32 {
        var result: i32 = 0;
        const size: usize = qr.size;

        // Adjacent modules in row having same color.
        for (0..size) |y| {
            var run_color = qr.getModule(0, @intCast(y));
            var run_len: usize = 1;
            for (1..size) |x| {
                const color = qr.getModule(@intCast(x), @intCast(y));
                if (color == run_color) {
                    run_len += 1;
                    if (run_len == 5) result += 3 else if (run_len > 5) result += 1;
                } else {
                    run_color = color;
                    run_len = 1;
                }
            }
        }

        // Adjacent modules in column having same color.
        for (0..size) |x| {
            var run_color = qr.getModule(@intCast(x), 0);
            var run_len: usize = 1;
            for (1..size) |y| {
                const color = qr.getModule(@intCast(x), @intCast(y));
                if (color == run_color) {
                    run_len += 1;
                    if (run_len == 5) result += 3 else if (run_len > 5) result += 1;
                } else {
                    run_color = color;
                    run_len = 1;
                }
            }
        }

        // 2x2 blocks of same color.
        for (0..size - 1) |y| {
            for (0..size - 1) |x| {
                const a = qr.getModule(@intCast(x), @intCast(y));
                const b = qr.getModule(@intCast(x + 1), @intCast(y));
                const c = qr.getModule(@intCast(x), @intCast(y + 1));
                const d = qr.getModule(@intCast(x + 1), @intCast(y + 1));
                if (a == b and b == c and c == d) result += 3;
            }
        }

        // Finder-like patterns.
        const pattern1 = [_]bool{ true, false, true, true, true, false, true, false, false, false, false };
        const pattern2 = [_]bool{ false, false, false, false, true, false, true, true, true, false, true };
        for (0..size) |y| {
            for (0..size - 10) |x| {
                var match1 = true;
                var match2 = true;
                for (0..11) |k| {
                    const color = qr.getModule(@intCast(x + k), @intCast(y));
                    if (color != pattern1[k]) match1 = false;
                    if (color != pattern2[k]) match2 = false;
                }
                if (match1 or match2) result += 40;
            }
        }
        for (0..size) |x| {
            for (0..size - 10) |y| {
                var match1 = true;
                var match2 = true;
                for (0..11) |k| {
                    const color = qr.getModule(@intCast(x), @intCast(y + k));
                    if (color != pattern1[k]) match1 = false;
                    if (color != pattern2[k]) match2 = false;
                }
                if (match1 or match2) result += 40;
            }
        }

        // Balance of black and white modules.
        var black: i32 = 0;
        for (qr.modules) |m| {
            if (m) black += 1;
        }
        const total: i32 = @intCast(qr.modules.len);
        const imbalance: i32 = black * 20 - total * 10;
        const k: i32 = @divTrunc(absI32(imbalance), total);
        result += k * 10;

        return result;
    }

    fn drawFormatBits(qr: *QRCode, ecc: ErrorCorrectionLevel, mask: u8) void {
        const ecc_bits: u32 = switch (ecc) {
            .L => 1,
            .M => 0,
            .Q => 3,
            .H => 2,
        };
        const data: u32 = (ecc_bits << 3) | mask;
        var rem: u32 = data << 10;
        const gen: u32 = 0x537;
        var i: i32 = 14;
        while (i >= 10) : (i -= 1) {
            if (((rem >> @intCast(i)) & 1) != 0) {
                rem ^= gen << @intCast(i - 10);
            }
        }
        const bits: u32 = (((data << 10) | (rem & 0x3FF)) ^ 0x5412);

        for (0..15) |j| {
            const bit = ((bits >> @intCast(j)) & 1) != 0;

            if (j < 6) {
                qr.setFunctionModule(8, @intCast(j), bit);
            } else if (j == 6) {
                qr.setFunctionModule(8, 7, bit);
            } else if (j == 7) {
                qr.setFunctionModule(8, 8, bit);
            } else if (j == 8) {
                qr.setFunctionModule(7, 8, bit);
            } else {
                qr.setFunctionModule(@intCast(14 - j), 8, bit);
            }

            if (j < 8) {
                qr.setFunctionModule(@intCast(qr.size - 1 - j), 8, bit);
            } else {
                qr.setFunctionModule(8, @intCast(qr.size - 15 + j), bit);
            }
        }
    }

    fn drawVersionBits(qr: *QRCode) void {
        var rem: u32 = @as(u32, qr.version) << 12;
        const gen: u32 = 0x1F25;
        var i: i32 = 17;
        while (i >= 12) : (i -= 1) {
            if (((rem >> @intCast(i)) & 1) != 0) {
                rem ^= gen << @intCast(i - 12);
            }
        }
        const bits: u32 = (@as(u32, qr.version) << 12) | (rem & 0xFFF);
        for (0..18) |j| {
            const bit = ((bits >> @intCast(j)) & 1) != 0;
            const x: u32 = qr.size - 11 + @as(u32, @intCast(j % 3));
            const y: u32 = @intCast(j / 3);
            qr.setFunctionModule(x, y, bit);
            qr.setFunctionModule(y, x, bit);
        }
    }
};

// Terminal Renderer
pub const TerminalRenderer = struct {
    pub fn render(file: std.fs.File, qr: *const QRCode, margin: u32) !void {
        const total_w: u32 = qr.size + margin * 2;
        const total_h: u32 = qr.size + margin * 2;

        var y: u32 = 0;
        while (y < total_h) : (y += 2) {
            var x: u32 = 0;
            while (x < total_w) : (x += 1) {
                const qr_x: i32 = @as(i32, @intCast(x)) - @as(i32, @intCast(margin));
                const qr_y_top: i32 = @as(i32, @intCast(y)) - @as(i32, @intCast(margin));
                const qr_y_bottom: i32 = qr_y_top + 1;

                const top = (qr_x >= 0 and qr_y_top >= 0 and qr_x < @as(i32, @intCast(qr.size)) and qr_y_top < @as(i32, @intCast(qr.size))) and
                    qr.getModule(@intCast(qr_x), @intCast(qr_y_top));
                const bottom = (qr_x >= 0 and qr_y_bottom >= 0 and qr_x < @as(i32, @intCast(qr.size)) and qr_y_bottom < @as(i32, @intCast(qr.size))) and
                    qr.getModule(@intCast(qr_x), @intCast(qr_y_bottom));

                if (top and bottom) {
                    try file.writeAll("█");
                } else if (top and !bottom) {
                    try file.writeAll("▀");
                } else if (!top and bottom) {
                    try file.writeAll("▄");
                } else {
                    try file.writeAll(" ");
                }
            }
            try file.writeAll("\n");
        }
    }

    pub fn renderANSI(file: std.fs.File, qr: *const QRCode, margin: u32) !void {
        const total: u32 = qr.size + margin * 2;
        for (0..total) |y| {
            for (0..total) |x| {
                const qr_x: i32 = @as(i32, @intCast(x)) - @as(i32, @intCast(margin));
                const qr_y: i32 = @as(i32, @intCast(y)) - @as(i32, @intCast(margin));
                const black = (qr_x >= 0 and qr_y >= 0 and qr_x < @as(i32, @intCast(qr.size)) and qr_y < @as(i32, @intCast(qr.size))) and
                    qr.getModule(@intCast(qr_x), @intCast(qr_y));
                if (black) {
                    try file.writeAll("\x1b[40m  \x1b[0m");
                } else {
                    try file.writeAll("\x1b[47m  \x1b[0m");
                }
            }
            try file.writeAll("\n");
        }
    }
};

// PNG Encoder (simplified)
pub const PNGEncoder = struct {
    pub fn writePNG(allocator: std.mem.Allocator, file_path: []const u8, qr: *const QRCode, scale: u32, margin: u32) !void {
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();
        try writePNGToFile(allocator, file, qr, scale, margin);
    }

    pub fn writePNGToFile(allocator: std.mem.Allocator, file: std.fs.File, qr: *const QRCode, scale: u32, margin: u32) !void {
        const width = (qr.size + margin * 2) * scale;
        const height = width;

        // Create pixel data (grayscale)
        const pixels = try allocator.alloc(u8, width * height);
        defer allocator.free(pixels);
        @memset(pixels, 255); // White background

        // Draw QR code
        for (0..qr.size) |y| {
            for (0..qr.size) |x| {
                const ux: u32 = @intCast(x);
                const uy: u32 = @intCast(y);
                if (qr.getModule(ux, uy)) {
                    const px = (margin + ux) * scale;
                    const py = (margin + uy) * scale;
                    for (0..scale) |dy| {
                        for (0..scale) |dx| {
                            const idx = (py + @as(u32, @intCast(dy))) * width + px + @as(u32, @intCast(dx));
                            if (idx < pixels.len) {
                                pixels[idx] = 0; // Black
                            }
                        }
                    }
                }
            }
        }

        try writePNGGrayscale8(allocator, file, pixels, width, height);
    }

    fn writePNGGrayscale8(allocator: std.mem.Allocator, file: std.fs.File, pixels: []const u8, width: u32, height: u32) !void {
        // PNG signature
        try file.writeAll(&[_]u8{ 137, 80, 78, 71, 13, 10, 26, 10 });

        // IHDR chunk
        try writeChunk(file, "IHDR", &[_]u8{
            @intCast(width >> 24), @intCast((width >> 16) & 0xFF),
            @intCast((width >> 8) & 0xFF), @intCast(width & 0xFF),
            @intCast(height >> 24), @intCast((height >> 16) & 0xFF),
            @intCast((height >> 8) & 0xFF), @intCast(height & 0xFF),
            8, // bit depth
            0, // grayscale
            0, // compression
            0, // filter
            0, // interlace
        });

        // IDAT chunk (zlib stream containing scanlines with filter bytes)
        var scanlines = std.ArrayList(u8){};
        defer scanlines.deinit(allocator);
        try scanlines.ensureTotalCapacity(allocator, (width + 1) * height);
        for (0..height) |y| {
            try scanlines.append(allocator, 0); // filter type 0
            const row_start: usize = @intCast(y * width);
            try scanlines.appendSlice(allocator, pixels[row_start .. row_start + width]);
        }

        const compressed = try zlibStore(allocator, scanlines.items);
        defer allocator.free(compressed);
        try writeChunk(file, "IDAT", compressed);

        // IEND chunk
        try writeChunk(file, "IEND", &[_]u8{});
    }

    fn zlibStore(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        var out = std.ArrayList(u8){};
        defer out.deinit(allocator);

        // zlib header: CMF/FLG for deflate + 32K window, fastest
        try out.appendSlice(allocator, &[_]u8{ 0x78, 0x01 });

        var remaining = data;
        while (remaining.len > 0) {
            const chunk_len: usize = @min(remaining.len, 0xFFFF);
            const is_final: u8 = if (chunk_len == remaining.len) 1 else 0;
            try out.append(allocator, is_final); // BFINAL + BTYPE(00)

            const len_u16: u16 = @intCast(chunk_len);
            const nlen_u16: u16 = ~len_u16;
            try out.appendSlice(allocator, &[_]u8{
                @intCast(len_u16 & 0xFF),
                @intCast((len_u16 >> 8) & 0xFF),
                @intCast(nlen_u16 & 0xFF),
                @intCast((nlen_u16 >> 8) & 0xFF),
            });
            try out.appendSlice(allocator, remaining[0..chunk_len]);
            remaining = remaining[chunk_len..];
        }

        const adler = adler32(data);
        try out.appendSlice(allocator, &[_]u8{
            @intCast((adler >> 24) & 0xFF),
            @intCast((adler >> 16) & 0xFF),
            @intCast((adler >> 8) & 0xFF),
            @intCast(adler & 0xFF),
        });

        return out.toOwnedSlice(allocator);
    }

    fn adler32(data: []const u8) u32 {
        var a: u32 = 1;
        var b: u32 = 0;
        for (data) |byte| {
            a = (a + byte) % 65521;
            b = (b + a) % 65521;
        }
        return (b << 16) | a;
    }

    fn writeChunk(file: std.fs.File, chunk_type: []const u8, data: []const u8) !void {
        // Length
        const len: u32 = @intCast(data.len);
        const len_bytes = [_]u8{
            @intCast(len >> 24),
            @intCast((len >> 16) & 0xFF),
            @intCast((len >> 8) & 0xFF),
            @intCast(len & 0xFF),
        };
        try file.writeAll(&len_bytes);

        // Type
        try file.writeAll(chunk_type);

        // Data
        try file.writeAll(data);

        // CRC
        var crc: u32 = 0xFFFFFFFF;
        for (chunk_type) |b| {
            crc = updateCRC(crc, b);
        }
        for (data) |b| {
            crc = updateCRC(crc, b);
        }
        crc ^= 0xFFFFFFFF;
        const crc_bytes = [_]u8{
            @intCast(crc >> 24),
            @intCast((crc >> 16) & 0xFF),
            @intCast((crc >> 8) & 0xFF),
            @intCast(crc & 0xFF),
        };
        try file.writeAll(&crc_bytes);
    }

    fn updateCRC(crc: u32, byte: u8) u32 {
        var c = crc ^ byte;
        for (0..8) |_| {
            c = if (c & 1 == 1) (c >> 1) ^ 0xEDB88320 else c >> 1;
        }
        return c;
    }
};

// SVG Encoder
pub const SVGEncoder = struct {
    pub fn writeSVG(file_path: []const u8, qr: *const QRCode, scale: u32, margin: u32) !void {
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();
        try writeSVGToFile(file, qr, scale, margin);
    }

    pub fn writeSVGToFile(file: std.fs.File, qr: *const QRCode, scale: u32, margin: u32) !void {
        const size = (qr.size + margin * 2) * scale;

        var buf: [1024]u8 = undefined;
        const header = try std.fmt.bufPrint(&buf,
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 {d} {d}">
            \\<rect width="{d}" height="{d}" fill="white"/>
            \\
        , .{ size, size, size, size });
        try file.writeAll(header);

        for (0..qr.size) |y| {
            for (0..qr.size) |x| {
                const ux: u32 = @intCast(x);
                const uy: u32 = @intCast(y);
                if (qr.getModule(ux, uy)) {
                    const px = (margin + ux) * scale;
                    const py = (margin + uy) * scale;
                    const rect = try std.fmt.bufPrint(&buf,
                        \\<rect x="{d}" y="{d}" width="{d}" height="{d}" fill="black"/>
                        \\
                    , .{ px, py, scale, scale });
                    try file.writeAll(rect);
                }
            }
        }

        try file.writeAll("</svg>\n");
    }
};

// QR Code Reader (Basic implementation)
pub const QRReader = struct {
    pub fn read(allocator: std.mem.Allocator, file_path: []const u8) ![]u8 {
        _ = allocator;
        _ = file_path;
        // QR code reading requires image processing libraries
        // This would need:
        // 1. Image loading (PNG, JPEG, etc.)
        // 2. QR code detection and localization
        // 3. Perspective correction
        // 4. Module reading
        // 5. Error correction and decoding
        //
        // For a full implementation, consider using:
        // - stb_image for image loading
        // - Computer vision algorithms for detection
        // - Reed-Solomon decoding for error correction

        return error.NotImplemented;
    }
};

// CLI Parser and Main
pub fn printHelp() void {
    const help =
        \\qrz - QR Code Generator CLI Tool v{s}
        \\
        \\USAGE:
        \\    qrz [OPTIONS] <data>
        //\\    qrz generate [OPTIONS] <data>
        //\\    qrz read [OPTIONS] <image_file>...
        \\
        //\\COMMANDS:
        //\\    generate    Generate a QR code from data (default)
        //\\    read        Read and decode QR code from image(s)
        \\
        \\GENERATE OPTIONS:
        \\    <data>                      Data to encode (required unless -i is used)
        \\    -i, --input <file>          Read data from file ("-" for stdin)
        \\    -o, --output <file>         Output file (default: stdout/terminal)
        \\    -t, --type <format>         Output format: png, txt, ansi, svg (default: png)
        \\    -e, --error <level>         Error correction: L, M, Q, H (default: M)
        \\    -s, --size <n>              Module size in pixels (default: 10)
        \\    -m, --margin <n>            Quiet zone margin in modules (default: 4)
        \\    --terminal                  Force terminal output
        \\    -h, --help                  Show this help message
        \\
        //\\READ OPTIONS:
        //\\    <image_file>...             Image file(s) to read
        //\\    --raw                       Output only decoded data
        //\\    -h, --help                  Show this help message
        //\\
        \\ERROR CORRECTION LEVELS:
        \\    L    Low     - 7% recovery
        \\    M    Medium  - 15% recovery (default)
        \\    Q    Quartile - 25% recovery
        \\    H    High    - 30% recovery
        \\
        \\EXAMPLES:
        //\\    qrz generate "any text"
        //\\    qrz generate -o qr.png -e H "https://example.com"
        //\\    qrz generate -t txt -m 2 "1234567890"
        //\\    qrz generate -i data.txt -o qr.svg -t svg
        \\    qrz "any text"
        \\    qrz -o qr.png -e H "https://example.com"
        \\    qrz -t txt -m 2 "1234567890"
        \\    qrz -i data.txt -o qr.svg -t svg
        \\    qrz -o qr.png -e H "https://example.com"
        //\\    qrz read qrcode.png
        //\\    qrz read --raw image1.png image2.png
        \\
    ;
    std.debug.print(help, .{VERSION});
}

fn parseArgsFrom(allocator: std.mem.Allocator, args: []const []const u8, emit_help: bool) !Config {
    var config = Config.init();
    if (args.len < 2) {
        if (emit_help) printHelp();
        return error.NoCommand;
    }

    // Check for help flag as first argument (standard CLI behavior).
    if (std.mem.eql(u8, args[1], "-h") or std.mem.eql(u8, args[1], "--help")) {
        if (emit_help) printHelp();
        return error.HelpRequested;
    }

    // Subcommand is optional: default to `generate` unless `read` is explicitly requested.
    // This enables: `qrz "google.com"` instead of `qrz generate "google.com"`.
    var i: usize = 1;
    if (std.mem.eql(u8, args[1], "generate") or std.mem.eql(u8, args[1], "read")) {
        config.command = try allocator.dupe(u8, args[1]);
        i = 2;
    } else {
        config.command = try allocator.dupe(u8, "generate");
        i = 1;
    }

    var end_of_opts = false;
    while (i < args.len) {
        const arg = args[i];

        if (!end_of_opts and std.mem.eql(u8, arg, "--")) {
            end_of_opts = true;
        } else if (!end_of_opts and (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help"))) {
            if (emit_help) printHelp();
            return error.HelpRequested;
        } else if (!end_of_opts and (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--input"))) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            config.input_file = try allocator.dupe(u8, args[i]);
        } else if (!end_of_opts and (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output"))) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            config.output_file = try allocator.dupe(u8, args[i]);
        } else if (!end_of_opts and (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--type"))) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            config.format = OutputFormat.fromString(args[i]) orelse return error.InvalidFormat;
        } else if (!end_of_opts and (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--error"))) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            config.error_level = ErrorCorrectionLevel.fromString(args[i]) orelse return error.InvalidErrorLevel;
        } else if (!end_of_opts and (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--size") or std.mem.eql(u8, arg, "--scale"))) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            config.size = try std.fmt.parseInt(u32, args[i], 10);
        } else if (!end_of_opts and (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--margin"))) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            config.margin = try std.fmt.parseInt(u32, args[i], 10);
        } else if (!end_of_opts and std.mem.eql(u8, arg, "--terminal")) {
            config.force_terminal = true;
        } else if (!end_of_opts and std.mem.eql(u8, arg, "--raw")) {
            config.raw_output = true;
        } else if (!end_of_opts and std.mem.startsWith(u8, arg, "-")) {
            return error.UnknownOption;
        } else {
            // Positional argument
            if (std.mem.eql(u8, config.command, "generate")) {
                if (config.data.len == 0) {
                    config.data = try allocator.dupe(u8, arg);
                } else {
                    // Likely missing quotes around <data> with spaces.
                    return error.TooManyArguments;
                }
            } else if (std.mem.eql(u8, config.command, "read")) {
                try config.image_files.append(allocator, try allocator.dupe(u8, arg));
            }
        }

        i += 1;
    }

    return config;
}

pub fn parseArgs(allocator: std.mem.Allocator) !Config {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    return parseArgsFrom(allocator, args, true);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var config = parseArgs(allocator) catch |err| {
        if (err == error.HelpRequested or err == error.NoCommand) {
            return;
        }
        std.debug.print("Error parsing arguments: {}\n", .{err});
        return err;
    };
    defer config.deinit(allocator);

    if (std.mem.eql(u8, config.command, "generate")) {
        try commandGenerate(allocator, &config);
    } else if (std.mem.eql(u8, config.command, "read")) {
        try commandRead(allocator, &config);
    } else {
        std.debug.print("Unknown command: {s}\n", .{config.command});
        std.debug.print("Use 'qrz --help' for usage information.\n", .{});
        return error.UnknownCommand;
    }
}

fn commandGenerate(allocator: std.mem.Allocator, config: *Config) !void {
    // Get data to encode
    var data_buf: []u8 = undefined;
    var data_owned = false;

    if (config.input_file) |input_file| {
        if (std.mem.eql(u8, input_file, "-")) {
            // Read from stdin
            const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
            data_buf = try stdin.readToEndAlloc(allocator, 1024 * 1024);
            data_owned = true;
        } else {
            // Read from file
            const file = try std.fs.cwd().openFile(input_file, .{});
            defer file.close();
            data_buf = try file.readToEndAlloc(allocator, 1024 * 1024);
            data_owned = true;
        }
    } else if (config.data.len > 0) {
        data_buf = @constCast(config.data);
    } else {
        std.debug.print("Error: No data provided. Use <data> or -i option.\n", .{});
        return error.NoData;
    }
    defer if (data_owned) allocator.free(data_buf);

    // Generate QR code
    var qr = try QREncoder.encode(allocator, data_buf, config.error_level);
    defer qr.deinit();

    // Output
    const stdout_file = std.fs.File.stdout();

    const wants_terminal = config.force_terminal or config.output_file == null;

    if (wants_terminal) {
        // Per spec: if no output path is provided, show terminal output (even if -t png/svg).
        if (config.format == .ANSI) {
            try TerminalRenderer.renderANSI(stdout_file, &qr, config.margin);
        } else {
            try TerminalRenderer.render(stdout_file, &qr, config.margin);
        }
    }

    if (config.output_file) |output_file| {
        if (std.mem.eql(u8, output_file, "-")) {
            // Explicit stdout output. If --terminal is also set, avoid mixing binary with text.
            if (config.force_terminal and (config.format == .PNG or config.format == .SVG)) {
                std.debug.print("Refusing to write {s} to stdout because --terminal is set; omit --terminal or use a file path.\n", .{@tagName(config.format)});
                return;
            }
            if (wants_terminal and (config.format == .TXT or config.format == .ANSI)) {
                // Already printed the terminal representation above.
                return;
            }

            switch (config.format) {
                .PNG => try PNGEncoder.writePNGToFile(allocator, stdout_file, &qr, config.size, config.margin),
                .SVG => try SVGEncoder.writeSVGToFile(stdout_file, &qr, config.size, config.margin),
                .TXT => try TerminalRenderer.render(stdout_file, &qr, config.margin),
                .ANSI => try TerminalRenderer.renderANSI(stdout_file, &qr, config.margin),
            }
        } else {
            switch (config.format) {
                .PNG => try PNGEncoder.writePNG(allocator, output_file, &qr, config.size, config.margin),
                .SVG => try SVGEncoder.writeSVG(output_file, &qr, config.size, config.margin),
                .TXT => {
                    const file = try std.fs.cwd().createFile(output_file, .{});
                    defer file.close();
                    try TerminalRenderer.render(file, &qr, config.margin);
                },
                .ANSI => {
                    const file = try std.fs.cwd().createFile(output_file, .{});
                    defer file.close();
                    try TerminalRenderer.renderANSI(file, &qr, config.margin);
                },
            }
            std.debug.print("QR code saved to: {s}\n", .{output_file});
        }
    }
}

fn commandRead(allocator: std.mem.Allocator, config: *Config) !void {
    if (config.image_files.items.len == 0) {
        std.debug.print("Error: No image files provided.\n", .{});
        return error.NoImageFiles;
    }

    for (config.image_files.items) |file_path| {
        if (!config.raw_output) {
            std.debug.print("Reading: {s}\n", .{file_path});
        }

        const result = QRReader.read(allocator, file_path) catch |err| {
            if (err == error.NotImplemented) {
                std.debug.print("Error: QR code reading is not yet implemented.\n", .{});
                std.debug.print("Reading QR codes requires additional image processing libraries:\n", .{});
                std.debug.print("  - Image loading (PNG, JPEG support)\n", .{});
                std.debug.print("  - Computer vision for QR detection\n", .{});
                std.debug.print("  - Perspective transformation\n", .{});
                std.debug.print("  - Reed-Solomon decoding\n\n", .{});
                std.debug.print("Consider using external tools like 'zbar' or 'zxing' for QR code reading.\n", .{});
            }
            return err;
        };
        defer allocator.free(result);

        if (config.raw_output) {
            std.debug.print("{s}\n", .{result});
        } else {
            std.debug.print("Decoded: {s}\n\n", .{result});
        }
    }
}

test "encode basic QR (version 1, M)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var qr = try QREncoder.encode(allocator, "Hello, World!", .M);
    defer qr.deinit();

    try std.testing.expectEqual(@as(u8, 1), qr.version);
    try std.testing.expectEqual(@as(u32, 21), qr.size);
    try std.testing.expect(qr.getModule(3, 3)); // Finder pattern center
    try std.testing.expect(qr.getModule(8, qr.size - 8)); // Dark module
}

test "CLI parsing: default generate without subcommand" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv = [_][]const u8{ "qrz", "google.com" };
    var cfg = try parseArgsFrom(allocator, &argv, false);
    defer cfg.deinit(allocator);

    try std.testing.expect(std.mem.eql(u8, cfg.command, "generate"));
    try std.testing.expect(std.mem.eql(u8, cfg.data, "google.com"));
}

test "CLI parsing: generate subcommand still works" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv = [_][]const u8{ "qrz", "generate", "-o", "out.png", "-e", "H", "hello" };
    var cfg = try parseArgsFrom(allocator, &argv, false);
    defer cfg.deinit(allocator);

    try std.testing.expect(std.mem.eql(u8, cfg.command, "generate"));
    try std.testing.expect(cfg.output_file != null);
    try std.testing.expect(std.mem.eql(u8, cfg.output_file.?, "out.png"));
    try std.testing.expect(cfg.error_level == .H);
    try std.testing.expect(std.mem.eql(u8, cfg.data, "hello"));
}

test "CLI parsing: read subcommand collects image files" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv = [_][]const u8{ "qrz", "read", "--raw", "a.png", "b.png" };
    var cfg = try parseArgsFrom(allocator, &argv, false);
    defer cfg.deinit(allocator);

    try std.testing.expect(std.mem.eql(u8, cfg.command, "read"));
    try std.testing.expect(cfg.raw_output);
    try std.testing.expectEqual(@as(usize, 2), cfg.image_files.items.len);
    try std.testing.expect(std.mem.eql(u8, cfg.image_files.items[0], "a.png"));
    try std.testing.expect(std.mem.eql(u8, cfg.image_files.items[1], "b.png"));
}

test "CLI parsing: help requested" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv = [_][]const u8{ "qrz", "--help" };
    try std.testing.expectError(error.HelpRequested, parseArgsFrom(allocator, &argv, false));
}
