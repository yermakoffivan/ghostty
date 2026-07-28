//! Snapshot record framing.
//!
//! Records begin immediately after the single snapshot envelope and continue
//! back-to-back until FINISH. Each record has one fixed-size header followed
//! by exactly `payload_len` bytes. The payload length limits the record reader
//! so malformed payloads cannot consume bytes from the following record.
//!
//! The CRC covers the first six header bytes (tag and payload length)
//! followed by the payload. The CRC field itself is not included for obvious
//! reasons. All integers are unsigned and little-endian.
//!
//! | Offset | Size          | Field                  |
//! | -----: | ------------: | :--------------------- |
//! |      0 |             2 | Tag (`u16`)            |
//! |      2 |             4 | Payload length (`u32`) |
//! |      6 |             4 | CRC32C (`u32`)         |
//! |     10 | `payload_len` | Payload                |
//!
//! Supported tags are in `Tag`.

const std = @import("std");
const io = @import("io.zig");

/// CRC32C as specified by the snapshot format. Zig names this standard
/// parameter set after its iSCSI use.
pub const Crc32c = std.hash.crc.Crc32Iscsi;

/// Identifies the layout and meaning of a record payload.
/// The current snapshot version rejects every value not listed here.
pub const Tag = enum(u16) {
    /// Terminal-wide live state and configuration.
    terminal = 1,

    /// One live screen and its page sequence.
    screen = 2,

    /// One complete logical terminal page.
    page = 3,

    /// Unfinished UTF-8 and terminal parser input.
    continuation = 4,

    /// Digest marking the validated terminal-state prefix.
    ready = 5,

    /// Digest validating the complete snapshot blob.
    finish = 6,
};

/// The fixed framing that precedes every record payload.
pub const Header = struct {
    /// Number of bytes written by `encode`, calculated using the encoder itself
    /// so this remains synchronized with the field-by-field wire format.
    pub const len = computeLen();

    comptime {
        // This size is part of the wire format. If it changes, the snapshot
        // version and golden fixtures must also change.
        std.debug.assert(len == 10);
    }

    /// Determines how the payload is decoded.
    tag: Tag,

    /// Number of payload bytes immediately following this header.
    payload_len: u32,

    /// CRC32C over the encoded tag, payload length, and payload.
    crc32c: u32,

    /// Errors possible while decoding a record header.
    pub const DecodeError = std.Io.Reader.Error || error{InvalidTag};

    /// Encode the fixed record header.
    pub fn encode(
        self: Header,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try encodeChecksumPrefix(self.tag, self.payload_len, writer);
        try io.writeInt(writer, u32, self.crc32c);
    }

    /// Decode a fixed record header and reject unknown tags.
    /// Payload length and CRC validation occur while decoding the payload.
    pub fn decode(reader: *std.Io.Reader) DecodeError!Header {
        const tag_raw = try io.readInt(reader, u16);
        const tag = std.enums.fromInt(Tag, tag_raw) orelse {
            return error.InvalidTag;
        };

        return .{
            .tag = tag,
            .payload_len = try io.readInt(reader, u32),
            .crc32c = try io.readInt(reader, u32),
        };
    }

    /// Computes the required header length at comptime.
    fn computeLen() usize {
        comptime {
            var buf: [128]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&buf);
            const header: Header = .{
                .tag = .terminal,
                .payload_len = 0,
                .crc32c = 0,
            };
            header.encode(&writer) catch unreachable;
            return writer.end;
        }
    }
};

/// A writer that calculates a record checksum without retaining payload bytes.
/// The checksum is initialized with the encoded tag and payload length.
pub const Checksum = struct {
    hashing: std.Io.Writer.Hashing(Crc32c),

    /// Begin a checksum with the encoded tag and payload length already added.
    pub fn init(tag: Tag, payload_len: u32) Checksum {
        var result: Checksum = .{
            .hashing = .initHasher(.init(), &.{}),
        };
        encodeChecksumPrefix(
            tag,
            payload_len,
            &result.hashing.writer,
        ) catch unreachable;
        return result;
    }

    /// Return the writer through which the complete payload must be encoded.
    pub fn writer(self: *Checksum) *std.Io.Writer {
        return &self.hashing.writer;
    }

    /// Finish and return the checksum stored in the record header.
    pub fn final(self: *Checksum) u32 {
        self.hashing.writer.flush() catch unreachable;
        return self.hashing.hasher.final();
    }
};

/// Builds one complete record.
///
/// This Writer requires an Allocating std.Io.Writer because the record
/// format requires reading the full payload and rewinding in order to
/// write the length + CRC without encoding twice.
pub const Writer = struct {
    destination: *std.Io.Writer.Allocating,
    tag: Tag,
    record_start: usize,

    /// Reserve space for a record at the current end of `destination`.
    /// Once this is called, callers MUST NOT write anything else to
    /// the writer until `finish` or `cancel` is called.
    pub fn init(
        destination: *std.Io.Writer.Allocating,
        tag: Tag,
    ) std.Io.Writer.Error!Writer {
        const record_start = destination.written().len;
        errdefer destination.shrinkRetainingCapacity(record_start);
        try destination.writer.splatByteAll(0, Header.len);
        return .{
            .destination = destination,
            .tag = tag,
            .record_start = record_start,
        };
    }

    /// Return the writer through which the payload is encoded exactly once.
    pub fn payloadWriter(self: *Writer) *std.Io.Writer {
        return &self.destination.writer;
    }

    pub const FinishError = error{
        /// The payload cannot be represented by the record's `u32` length.
        PayloadTooLarge,
    };

    /// Marked the completed record with the payload length and CRC32C.
    pub fn finish(self: *Writer) FinishError!void {
        const bytes = self.destination.written();
        const payload_start = self.record_start + Header.len;
        const payload_len = std.math.cast(
            u32,
            bytes.len - payload_start,
        ) orelse return error.PayloadTooLarge;
        const payload = bytes[payload_start..];

        // Calculate our CRC
        var checksum: Checksum = .init(self.tag, payload_len);
        checksum.writer().writeAll(payload) catch unreachable;

        // Build the header and encode it directly into the header
        const header: Header = .{
            .tag = self.tag,
            .payload_len = payload_len,
            .crc32c = checksum.final(),
        };
        var header_writer: std.Io.Writer = .fixed(bytes[self.record_start..payload_start]);
        header.encode(&header_writer) catch unreachable;
    }

    /// Discard this record. This makes it safe to use the underlying
    /// alloating writer again as if nothing happened.
    pub fn cancel(self: *Writer) void {
        self.destination.shrinkRetainingCapacity(self.record_start);
    }
};

/// Reads one complete record.
///
/// `init` decodes the header, `payloadReader` returns a reader limited to the
/// declared payload, and `finish` verifies exact exhaustion and the CRC32C.
pub const Reader = struct {
    header: Header,

    // The limited reader normally streams directly into the hashing reader's
    // buffer. One byte is enough for operations that require it to buffer,
    // such as peek and discard.
    limited_buffer: [1]u8,

    // PAGE decoding performs many small reads. 256 bytes batches several cells
    // while CRC32C is calculated without making Reader large on the stack.
    hashing_buffer: [256]u8,

    limited: std.Io.Reader.Limited,
    hashing: std.Io.Reader.Hashed(Crc32c),

    pub const InitError = Header.DecodeError;

    /// Errors detected after a payload decoder returns.
    pub const FinishError = error{
        /// The payload bytes do not match the CRC in the record header.
        InvalidChecksum,

        /// The decoder did not consume exactly `payload_len` bytes.
        PayloadNotExhausted,
    };

    /// Decode a record header and initialize its payload reader.
    ///
    /// `self` must remain at a stable address until `finish` returns. Decode
    /// the payload only through the reader returned by `payloadReader`.
    pub fn init(
        self: *Reader,
        source: *std.Io.Reader,
    ) InitError!void {
        self.* = undefined;
        self.header = try Header.decode(source);
        self.limited = .init(
            source,
            .limited(self.header.payload_len),
            &self.limited_buffer,
        );

        const checksum: Checksum = .init(
            self.header.tag,
            self.header.payload_len,
        );
        self.hashing = .init(
            &self.limited.interface,
            checksum.hashing.hasher,
            &self.hashing_buffer,
        );
    }

    /// Return the length-limited, checksum-updating payload reader.
    pub fn payloadReader(self: *Reader) *std.Io.Reader {
        return &self.hashing.reader;
    }

    /// Require exact payload exhaustion and validate its CRC32C.
    pub fn finish(self: *Reader) FinishError!void {
        if (self.hashing.reader.bufferedLen() != 0 or
            self.limited.remaining != .nothing)
        {
            return error.PayloadNotExhausted;
        }

        if (self.hashing.hasher.final() != self.header.crc32c) {
            return error.InvalidChecksum;
        }
    }
};

/// Encode the portion of a record header covered by CRC32C.
fn encodeChecksumPrefix(
    tag: Tag,
    payload_len: u32,
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    try io.writeInt(writer, u16, @intFromEnum(tag));
    try io.writeInt(writer, u32, payload_len);
}

test "golden PAGE record header and checksum" {
    const page_header =
        "\x50\x00\x18\x00\x00\x00\x00\x00" ++
        "\x00\x00\x00\x00\x00\x00\x00\x00" ++
        "\x00\x00\x00\x00\x00\x00\x00\x00";

    var checksum: Checksum = .init(.page, page_header.len);
    try checksum.writer().writeAll(page_header);
    try std.testing.expectEqual(@as(u32, 0x7178441b), checksum.final());

    const header: Header = .{
        .tag = .page,
        .payload_len = page_header.len,
        .crc32c = 0x7178441b,
    };
    var buf: [Header.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try header.encode(&writer);

    try std.testing.expectEqualStrings(
        "\x03\x00\x18\x00\x00\x00\x1b\x44\x78\x71",
        writer.buffered(),
    );
}

test "reject invalid tags" {
    for ([_]u16{ 0, 7, std.math.maxInt(u16) }) |tag| {
        var fixture = [_]u8{0} ** Header.len;
        std.mem.writeInt(u16, fixture[0..2], tag, .little);
        var reader: std.Io.Reader = .fixed(&fixture);
        try std.testing.expectError(error.InvalidTag, Header.decode(&reader));
    }
}

test "reject every header truncation" {
    const fixture = "\x03\x00\x18\x00\x00\x00\x1b\x44\x78\x71";
    for (0..Header.len) |len| {
        var reader: std.Io.Reader = .fixed(fixture[0..len]);
        try std.testing.expectError(error.EndOfStream, Header.decode(&reader));
    }
}

test "record reader verifies exhaustion and checksum" {
    const payload = "snapshot payload";
    var checksum: Checksum = .init(.page, payload.len);
    try checksum.writer().writeAll(payload);
    const header: Header = .{
        .tag = .page,
        .payload_len = payload.len,
        .crc32c = checksum.final(),
    };

    var encoded: [Header.len + payload.len + 4]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try header.encode(&writer);
    try writer.writeAll(payload ++ "next");

    var source: std.Io.Reader = .fixed(writer.buffered());
    var record_reader: Reader = undefined;
    try record_reader.init(&source);
    var decoded: [payload.len]u8 = undefined;
    try record_reader.payloadReader().readSliceAll(&decoded);
    try record_reader.finish();
    try std.testing.expectEqualStrings(payload, &decoded);
    try std.testing.expectEqualStrings("next", try source.take(4));
}

test "record reader rejects remaining bytes and invalid checksum" {
    const payload = "payload";
    const header: Header = .{
        .tag = .page,
        .payload_len = payload.len,
        .crc32c = 0,
    };

    var encoded: [Header.len + payload.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try header.encode(&writer);
    try writer.writeAll(payload);

    {
        var source: std.Io.Reader = .fixed(writer.buffered());
        var record_reader: Reader = undefined;
        try record_reader.init(&source);
        _ = try record_reader.payloadReader().takeByte();
        try std.testing.expectError(
            error.PayloadNotExhausted,
            record_reader.finish(),
        );
    }

    {
        var source: std.Io.Reader = .fixed(writer.buffered());
        var record_reader: Reader = undefined;
        try record_reader.init(&source);
        try record_reader.payloadReader().discardAll(payload.len);
        try std.testing.expectError(
            error.InvalidChecksum,
            record_reader.finish(),
        );
    }
}

test "payload limit does not consume the next record" {
    const payload = "ab";
    var checksum: Checksum = .init(.page, payload.len);
    try checksum.writer().writeAll(payload);
    const header: Header = .{
        .tag = .page,
        .payload_len = payload.len,
        .crc32c = checksum.final(),
    };

    var encoded: [Header.len + payload.len + 4]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try header.encode(&writer);
    try writer.writeAll(payload ++ "next");

    var source: std.Io.Reader = .fixed(writer.buffered());
    var record_reader: Reader = undefined;
    try record_reader.init(&source);
    var too_long: [3]u8 = undefined;
    try std.testing.expectError(
        error.EndOfStream,
        record_reader.payloadReader().readSliceAll(&too_long),
    );
    try record_reader.finish();
    try std.testing.expectEqualStrings("next", try source.take(4));
}

test "record writer appends and backpatches framing" {
    var destination: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer destination.deinit();
    try destination.writer.writeAll("prefix");

    var record_writer = try Writer.init(&destination, .page);
    try record_writer.payloadWriter().writeAll("payload");
    try record_writer.finish();

    const encoded = destination.written();
    try std.testing.expectEqualStrings("prefix", encoded[0..6]);

    var source: std.Io.Reader = .fixed(encoded[6..]);
    var record_reader: Reader = undefined;
    try record_reader.init(&source);
    try std.testing.expectEqual(Tag.page, record_reader.header.tag);
    try std.testing.expectEqual(
        @as(u32, 7),
        record_reader.header.payload_len,
    );
    try std.testing.expectEqualStrings(
        "payload",
        try record_reader.payloadReader().take(7),
    );
    try record_reader.finish();
}

test "record writer cancel preserves preceding bytes" {
    var destination: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer destination.deinit();
    try destination.writer.writeAll("prefix");

    var record_writer = try Writer.init(&destination, .page);
    try record_writer.payloadWriter().writeAll("partial");
    record_writer.cancel();

    try std.testing.expectEqualStrings("prefix", destination.written());
}
