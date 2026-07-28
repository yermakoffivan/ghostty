//! PAGE record payload encoding.
//!
//! One PAGE record represents a set of rows/columns in the terminal.
//! In libghostty, this happens to map internally to a very specific
//! data structure called a "page" (hence the name), but consumers of
//! the format don't need to reproduce that.
//!
//! The important thing is that one page is fully self-contained: it has
//! a dimension (cols x rows), a set of styles, hyperlinks, cells, etc.
//! and depends on no external state to decode that with some exceptions
//! like assets such as images.
//!
//! A page could have a dimension that doesn't match the terminal
//! dimensions, e.g. for lazy resize/reflow. Callers must be prepared for
//! that.
//!
//! ## Binary Format
//!
//! Every PAGE payload begins with a fixed header, followed by a
//! payload of styles, hyperlinks, and rows and columns.
//!
//! All integers are unsigned and little-endian.
//!
//! ### Header
//!
//! | Offset | Size | Field                              |
//! | -----: | ---: | :--------------------------------- |
//! |      0 |    2 | Logical columns (`u16`)            |
//! |      2 |    2 | Logical rows (`u16`)               |
//! |      4 |    2 | Non-default style count (`u16`)    |
//! |      6 |    2 | Unique hyperlink count (`u16`)     |
//! |      8 |    2 | Style capacity hint (`u16`)        |
//! |     10 |    2 | Hyperlink capacity bytes (`u16`)   |
//! |     12 |    4 | Grapheme capacity bytes (`u32`)    |
//! |     16 |    4 | String capacity bytes (`u32`)      |
//!
//! The first two fields (columns and rows) denote the dimensionality
//! of the page. The payload is guaranteed to have this dimensionality;
//! every row has exactly the columns specified.
//!
//! Next, the style count and hyperlink count denote the number of
//! styles and hyperlinks respectively that are sent with the page.
//! The default style and absence of a hyperlink are implicit at native
//! ID zero and are not included in these counts. Each encoded table entry
//! carries its nonzero native page ID.
//!
//! The final four fields are allocation hints copied from the source page.
//! These represent upper limits on what this page might contain. A decoder
//! can optionally choose to use this for preallocation or it can ignore
//! and decode and allocate dynamically.
//!
//! ### Payload
//!
//! ```text
//! +---------------------------+
//! | Header                    |
//! | 20 bytes                  |
//! +---------------------------+
//! | Style table               |
//! | style_count entries       |
//! +---------------------------+
//! | Hyperlink table           |
//! | hyperlink_count entries   |
//! +---------------------------+
//! | Grid                      |
//! | one record per row        |
//! +---------------------------+
//!
//! Style entry     = encoded ID + style record
//! Hyperlink entry = encoded ID + hyperlink record
//! Grid            = row 0 ... row (rows - 1)
//! Row             = row header + cell 0 ... cell (columns - 1)
//! Cell            = cell header + grapheme suffix codepoints
//! ```
//!
//! Following the header, the payload contains exactly `style_count` style
//! records and `hyperlink_count` hyperlink records, followed by exactly
//! `rows` row records. There is no padding between records.
//!
//! Each style begins with an ID (`u16`) followed by the typical style
//! binary representation (in style.zig). The ID is what cells will use
//! to reference the style. Decoders must maintain some kind of mapping
//! in order to associate these properly.
//!
//! Each hyperlink also begins with an ID (`u16`) with the same semantics
//! as the style ID. The hyperlink and style IDs are separate namespaces,
//! so they may collide. Following the ID, the hyperlink binary format
//! is encoded directly.
//!
//! Both style and hyperlink IDs are not guaranteed to be in any specific
//! order and may contain gaps (e.g. ID 1 and 3 but not 2).
//!
//! Rows and cells use the grid encoding documented in `grid.zig`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const envelope = @import("envelope.zig");
const grid = @import("grid.zig");
const hyperlink = @import("hyperlink.zig");
const io = @import("io.zig");
const record = @import("record.zig");
const style = @import("style.zig");
const terminal_hyperlink = @import("../hyperlink.zig");
const terminal_page = @import("../page.zig");
const terminal_style = @import("../style.zig");

// Frequent constants we use
const TerminalHyperlink = terminal_hyperlink.Hyperlink;
const TerminalHyperlinkId = terminal_hyperlink.Id;
const TerminalHyperlinkPageEntry = terminal_hyperlink.PageEntry;
const TerminalHyperlinkSet = terminal_hyperlink.Set;
const TerminalCell = terminal_page.Cell;
const TerminalPage = terminal_page.Page;
const TerminalPageCapacity = terminal_page.Capacity;
const TerminalRow = terminal_page.Row;
const TerminalStyle = terminal_style.Style;
const TerminalStyleId = terminal_style.Id;
const TerminalStyleSet = terminal_style.Set;

const PayloadEncodeError = hyperlink.EncodeError || grid.EncodeError;

const PayloadDecodeError = style.DecodeError ||
    grid.DecodeError ||
    Header.CapacityError ||
    error{
        /// The hyperlink kind is not defined by snapshot version 1.
        InvalidKind,

        /// The advertised string capacity cannot hold the encoded hyperlinks.
        InvalidStringCapacity,

        /// A non-default style was encoded more than once.
        DuplicateStyle,

        /// A hyperlink was encoded more than once.
        DuplicateHyperlink,

        /// The default style cannot appear in the non-default style table.
        DefaultStyle,

        /// An encoded table ID is zero or appears more than once.
        InvalidStyleId,
        InvalidHyperlinkId,

        /// Native page backing memory could not be allocated.
        OutOfMemory,
    };

/// Errors possible while encoding a complete PAGE record.
pub const EncodeError = PayloadEncodeError || record.Writer.FinishError;

/// Encode one complete PAGE record from a native page.
///
/// The record is appended to `destination`. Its header is reserved before the
/// payload is encoded, then backpatched with the payload length and CRC32C. If
/// encoding fails, the partial record is removed while earlier bytes remain.
pub fn encode(
    page: *const TerminalPage,
    destination: *std.Io.Writer.Allocating,
) EncodeError!void {
    var record_writer = try record.Writer.init(destination, .page);
    errdefer record_writer.cancel();
    try encodePayload(page, record_writer.payloadWriter());
    try record_writer.finish();
}

/// Errors possible while decoding and validating a complete PAGE record.
pub const DecodeError = PayloadDecodeError ||
    record.Reader.InitError ||
    record.Reader.FinishError ||
    TerminalPage.IntegrityError ||
    error{
        /// The next record is valid but is not a PAGE.
        UnexpectedRecordTag,
    };

/// Decode and validate one complete PAGE record into a fresh native page.
///
/// The record tag, payload boundary, CRC32C, payload contents, and final page
/// integrity are all validated before the page is returned. `alloc` is used
/// only for temporary decode remaps and integrity-check storage.
pub fn decode(
    reader: *std.Io.Reader,
    alloc: Allocator,
) DecodeError!TerminalPage {
    var record_reader: record.Reader = undefined;
    try record_reader.init(reader);
    if (record_reader.header.tag != .page) return error.UnexpectedRecordTag;

    var page = try decodePayload(record_reader.payloadReader(), alloc);
    errdefer page.deinit();
    try record_reader.finish();
    try page.verifyIntegrity(alloc);
    return page;
}

/// Encode a PAGE payload directly from a native page.
fn encodePayload(
    page: *const TerminalPage,
    writer: *std.Io.Writer,
) PayloadEncodeError!void {
    // Write header
    try Header.init(page).encode(writer);

    // Sparse styles
    var style_it = page.styles.iterator(page.memory);
    while (style_it.next()) |entry| {
        try io.writeInt(writer, TerminalStyleId, entry.id);
        try style.encode(entry.value_ptr.*, writer);
    }

    // Sparse hyperlinks
    var hyperlink_it = page.hyperlink_set.iterator(page.memory);
    while (hyperlink_it.next()) |entry| {
        try io.writeInt(writer, TerminalHyperlinkId, entry.id);
        try hyperlink.encode(pageHyperlink(page, entry.value_ptr), writer);
    }

    // Rows and cells
    try grid.encode(page, writer);
}

/// Decode a PAGE payload directly into a fresh native page.
///
/// `alloc` is used only for the temporary native-ID remap tables. Styles,
/// hyperlinks, strings, graphemes, rows, and cells are stored in the page.
fn decodePayload(
    reader: *std.Io.Reader,
    alloc: Allocator,
) PayloadDecodeError!TerminalPage {
    // Decode the header, validate capacities, init page
    const header = try Header.decode(reader);
    const capacity = try header.pageCapacity();
    var page = TerminalPage.init(capacity) catch
        return error.OutOfMemory;
    errdefer page.deinit();
    page.pauseIntegrityChecks(true);
    defer page.pauseIntegrityChecks(false);

    var style_remap = grid.StyleRemap.init(alloc);
    defer style_remap.deinit();
    style_remap.ensureTotalCapacity(header.style_count) catch
        return error.OutOfMemory;

    var hyperlink_remap = grid.HyperlinkRemap.init(alloc);
    defer hyperlink_remap.deinit();
    hyperlink_remap.ensureTotalCapacity(header.hyperlink_count) catch
        return error.OutOfMemory;

    // Styles
    for (0..header.style_count) |_| {
        // Zero denotes the implicit default style. Reusing an encoded ID would
        // make cell references ambiguous because it would name multiple table
        // entries.
        const native_id = try io.readInt(reader, TerminalStyleId);
        if (native_id == 0 or style_remap.contains(native_id)) {
            return error.InvalidStyleId;
        }

        // Decode the style itself. It must never be the default style.
        const value = try style.decode(reader);
        if (value.default()) return error.DefaultStyle;

        // If we already have the style, its invalid.
        if (page.styles.lookup(
            page.memory,
            value,
        ) != null) return error.DuplicateStyle;

        // Add our style, get our real ID on this side, and store it in the
        // remap table.
        const decoded_id = page.styles.add(
            page.memory,
            value,
        ) catch |err| switch (err) {
            error.OutOfMemory,
            error.NeedsRehash,
            => return error.InvalidStyleCapacity,
        };
        style_remap.putAssumeCapacityNoClobber(
            native_id,
            decoded_id,
        );
    }

    // Hyperlinks
    for (0..header.hyperlink_count) |_| {
        // Zero denotes no hyperlink. As with styles, a repeated encoded ID
        // would make cell references ambiguous.
        const native_id = try io.readInt(reader, TerminalHyperlinkId);
        if (native_id == 0 or hyperlink_remap.contains(native_id)) {
            return error.InvalidHyperlinkId;
        }

        const decoded_id = hyperlink.decodePage(
            &page,
            reader,
        ) catch |err| switch (err) {
            error.StringsOutOfMemory => return error.InvalidStringCapacity,
            error.SetOutOfMemory,
            error.SetNeedsRehash,
            => return error.InvalidHyperlinkCapacity,

            error.DuplicateHyperlink => return error.DuplicateHyperlink,
            error.InvalidKind => return error.InvalidKind,
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed => return error.ReadFailed,
        };
        hyperlink_remap.putAssumeCapacityNoClobber(
            native_id,
            decoded_id,
        );
    }

    // Rows and cells
    try grid.decode(
        &page,
        reader,
        &style_remap,
        &hyperlink_remap,
    );

    return page;
}

/// The fixed logical dimensions, table counts, and allocation hints at the
/// start of PAGE.
pub const Header = struct {
    /// Number of bytes written by `encode`, calculated using the encoder itself
    /// so this remains synchronized with the field-by-field wire format.
    pub const len = computeLen();

    comptime {
        // This size is part of the wire format. If it changes, the snapshot
        // version and golden fixtures must also change.
        std.debug.assert(len == 20);
    }

    /// Number of logical cells in every encoded row.
    columns: u16,

    /// Number of logical rows encoded after the tables.
    rows: u16,

    /// Number of non-default style entries following the header.
    style_count: u16,

    /// Number of unique hyperlink entries following the style table.
    hyperlink_count: u16,

    /// Suggested capacity for the native non-default style set.
    style_capacity: u16,

    /// Suggested native hyperlink storage capacity in bytes.
    hyperlink_capacity_bytes: u16,

    /// Suggested native grapheme storage capacity in bytes.
    grapheme_capacity_bytes: u32,

    /// Suggested native string storage capacity in bytes.
    string_capacity_bytes: u32,

    /// Encode the fixed PAGE payload header.
    pub fn encode(
        self: Header,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try io.writeInt(writer, u16, self.columns);
        try io.writeInt(writer, u16, self.rows);
        try io.writeInt(writer, u16, self.style_count);
        try io.writeInt(writer, u16, self.hyperlink_count);
        try io.writeInt(writer, u16, self.style_capacity);
        try io.writeInt(writer, u16, self.hyperlink_capacity_bytes);
        try io.writeInt(writer, u32, self.grapheme_capacity_bytes);
        try io.writeInt(writer, u32, self.string_capacity_bytes);
    }

    /// Decode the fixed PAGE payload header.
    ///
    /// This reads field values only. The complete PAGE decoder is responsible
    /// for applying configured limits before using any capacity hint.
    pub fn decode(reader: *std.Io.Reader) std.Io.Reader.Error!Header {
        return .{
            .columns = try io.readInt(reader, u16),
            .rows = try io.readInt(reader, u16),
            .style_count = try io.readInt(reader, u16),
            .hyperlink_count = try io.readInt(reader, u16),
            .style_capacity = try io.readInt(reader, u16),
            .hyperlink_capacity_bytes = try io.readInt(reader, u16),
            .grapheme_capacity_bytes = try io.readInt(reader, u32),
            .string_capacity_bytes = try io.readInt(reader, u32),
        };
    }

    /// Initialize a header from the current contents of a native page.
    ///
    /// This copies the page's existing allocation capacities. It does not
    /// scan cells, allocate, or encode any bytes.
    fn init(page: *const TerminalPage) Header {
        return .{
            .columns = page.size.cols,
            .rows = page.size.rows,
            .style_count = @intCast(page.styles.count()),
            .hyperlink_count = @intCast(page.hyperlink_set.count()),
            .style_capacity = page.capacity.styles,
            .hyperlink_capacity_bytes = page.capacity.hyperlink_bytes,
            .grapheme_capacity_bytes = page.capacity.grapheme_bytes,
            .string_capacity_bytes = page.capacity.string_bytes,
        };
    }

    pub const CapacityError = error{
        InvalidDimensions,
        InvalidStyleCapacity,
        InvalidHyperlinkCapacity,
    };

    /// Validate native allocation requirements and produce the page capacity.
    fn pageCapacity(self: Header) CapacityError!TerminalPageCapacity {
        if (self.columns == 0 or self.rows == 0) {
            return error.InvalidDimensions;
        }

        const style_layout: TerminalStyleSet.Layout = .init(self.style_capacity);
        if (self.style_count > style_layout.cap -| 1) {
            return error.InvalidStyleCapacity;
        }

        const hyperlink_capacity_count = @divFloor(
            self.hyperlink_capacity_bytes,
            @sizeOf(TerminalHyperlinkSet.Item),
        );
        const hyperlink_layout: TerminalHyperlinkSet.Layout = .init(
            hyperlink_capacity_count,
        );
        if (self.hyperlink_count > hyperlink_layout.cap -| 1) {
            return error.InvalidHyperlinkCapacity;
        }

        return .{
            .cols = self.columns,
            .rows = self.rows,
            .styles = self.style_capacity,
            .hyperlink_bytes = self.hyperlink_capacity_bytes,
            .grapheme_bytes = self.grapheme_capacity_bytes,
            .string_bytes = self.string_capacity_bytes,
        };
    }

    fn computeLen() usize {
        var buf: [128]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        const header: Header = .{
            .columns = 0,
            .rows = 0,
            .style_count = 0,
            .hyperlink_count = 0,
            .style_capacity = 0,
            .hyperlink_capacity_bytes = 0,
            .grapheme_capacity_bytes = 0,
            .string_capacity_bytes = 0,
        };
        header.encode(&writer) catch unreachable;
        return writer.end;
    }
};

fn pageHyperlink(
    page: *const TerminalPage,
    entry: *const TerminalHyperlinkPageEntry,
) TerminalHyperlink {
    return .{
        .id = switch (entry.id) {
            .implicit => |value| .{ .implicit = value },
            .explicit => |value| .{ .explicit = value.slice(page.memory) },
        },
        .uri = entry.uri.slice(page.memory),
    };
}

// Regenerate these after a wire-format change from `writer.buffered()` in the
// sparse-page test and `destination.written()` in the empty-record test below.
// Format those byte slices as Zig-escaped strings before replacing the literals.
const test_page_fixture =
    "\x03\x00\x02\x00\x02\x00\x02\x00\x08\x00\x00\x02\x80\x00\x00\x00" ++
    "\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++
    "\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x01\x2a\x00\x00" ++
    "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x01\x00\x00\x00\x61" ++
    "\x05\x00\x00\x00\x61\x6c\x70\x68\x61\x03\x00\x01\x04\x03\x02\x01" ++
    "\x04\x00\x00\x00\x62\x65\x74\x61\x04\x00\x01\x05\x00\x01\x00\x01" ++
    "\x00\x41\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02\x00\x03\x00\x03" ++
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x01" ++
    "\x00\x07\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x00\x00\x00" ++
    "\x00\x00\x78\x00\x00\x00\x02\x00\x00\x00\x01\x03\x00\x00\x02\x03" ++
    "\x00\x00\x02\x00\x01\x00\x00\x00\x00\x00\xaa\xbb\xcc\x00\x00\x00" ++
    "\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++
    "\x00\x00";

const test_empty_framed_page_fixture =
    // Record header: PAGE, 37-byte payload, CRC32C.
    "\x03\x00\x25\x00\x00\x00\x8c\x05\xd6\xd3" ++
    // PAGE header: one column, one row, and zero counts/capacities.
    "\x01\x00\x01\x00\x00\x00\x00\x00" ++
    "\x00\x00\x00\x00\x00\x00\x00\x00" ++
    "\x00\x00\x00\x00" ++
    // One default row and one empty cell.
    "\x00\x00\x00\x00\x00\x00\x00\x00" ++
    "\x00\x00\x00\x00\x00\x00\x00\x00" ++
    "\x00";

test "golden encoding" {
    const header: Header = .{
        .columns = 0x0102,
        .rows = 0x0304,
        .style_count = 0x0506,
        .hyperlink_count = 0x0708,
        .style_capacity = 0x090a,
        .hyperlink_capacity_bytes = 0x0b0c,
        .grapheme_capacity_bytes = 0x0d0e0f10,
        .string_capacity_bytes = 0x11121314,
    };

    var buf: [Header.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try header.encode(&writer);

    try std.testing.expectEqualStrings(
        "\x02\x01\x04\x03\x06\x05\x08\x07" ++
            "\x0a\x09\x0c\x0b\x10\x0f\x0e\x0d" ++
            "\x14\x13\x12\x11",
        writer.buffered(),
    );
}

test "decode with a one-byte reader buffer" {
    const fixture =
        "\x02\x01\x04\x03\x06\x05\x08\x07" ++
        "\x0a\x09\x0c\x0b\x10\x0f\x0e\x0d" ++
        "\x14\x13\x12\x11";
    var source: std.Io.Reader = .fixed(fixture);
    var buf: [1]u8 = undefined;
    var limited = source.limited(.unlimited, &buf);

    try std.testing.expectEqual(
        Header{
            .columns = 0x0102,
            .rows = 0x0304,
            .style_count = 0x0506,
            .hyperlink_count = 0x0708,
            .style_capacity = 0x090a,
            .hyperlink_capacity_bytes = 0x0b0c,
            .grapheme_capacity_bytes = 0x0d0e0f10,
            .string_capacity_bytes = 0x11121314,
        },
        try Header.decode(&limited.interface),
    );
}

test "reject every truncation" {
    const fixture =
        "\x02\x01\x04\x03\x06\x05\x08\x07" ++
        "\x0a\x09\x0c\x0b\x10\x0f\x0e\x0d" ++
        "\x14\x13\x12\x11";
    for (0..Header.len) |len| {
        var reader: std.Io.Reader = .fixed(fixture[0..len]);
        try std.testing.expectError(error.EndOfStream, Header.decode(&reader));
    }
}

test "framed PAGE encode and decode a sparse native page" {
    const capacity: TerminalPageCapacity = .{
        .cols = 3,
        .rows = 2,
        .styles = 8,
        .hyperlink_bytes = 512,
        .grapheme_bytes = 128,
        .string_bytes = 256,
    };
    var page = try TerminalPage.init(capacity);
    defer page.deinit();

    // Create holes in both source tables so the encoded IDs exercise sparse
    // table remapping rather than coincidentally matching decoded IDs.
    const style_a = try page.styles.add(page.memory, .{
        .flags = .{ .bold = true },
    });
    const dead_style = try page.styles.add(page.memory, .{
        .flags = .{ .italic = true },
    });
    const style_b = try page.styles.add(page.memory, .{
        .bg_color = .{ .palette = 42 },
    });
    page.styles.release(page.memory, dead_style);

    const first = page.getRowAndCell(0, 0);
    first.cell.style_id = style_a;
    first.row.styled = true;

    const second = page.getRowAndCell(1, 0);
    second.cell.style_id = style_b;
    second.row.styled = true;

    const third = page.getRowAndCell(2, 0);
    page.styles.use(page.memory, style_a);
    third.cell.style_id = style_a;
    third.row.styled = true;

    const hyperlink_a = try page.insertHyperlink(.{
        .id = .{ .explicit = "a" },
        .uri = "alpha",
    });
    const dead_hyperlink = try page.insertHyperlink(.{
        .id = .{ .explicit = "dead-id" },
        .uri = "dead-uri",
    });
    const hyperlink_b = try page.insertHyperlink(.{
        .id = .{ .implicit = 0x01020304 },
        .uri = "beta",
    });
    page.hyperlink_set.release(page.memory, dead_hyperlink);

    page.hyperlink_set.use(page.memory, hyperlink_a);
    try page.setHyperlink(first.row, first.cell, hyperlink_a);
    try page.setHyperlink(second.row, second.cell, hyperlink_b);
    try page.setHyperlink(third.row, third.cell, hyperlink_a);

    // Cover graphemes, wide-cell pairs, colors, protection, and semantic
    // metadata in one compact two-row page.
    const grapheme = page.getRowAndCell(0, 1);
    grapheme.cell.* = .init('x');
    try page.setGraphemes(
        grapheme.row,
        grapheme.cell,
        &.{ 0x0301, 0x0302 },
    );

    first.cell.content = .{ .codepoint = .{ .data = 'A' } };
    first.cell.wide = .wide;
    first.cell.protected = true;
    first.cell.semantic_content = .prompt;
    first.row.semantic_prompt = .prompt;

    second.cell.wide = .spacer_tail;
    second.cell.semantic_content = .input;

    third.cell.content_tag = .bg_color_palette;
    third.cell.content = .{ .color_palette = .{ .data = 7 } };

    const rgb = page.getRowAndCell(1, 1);
    rgb.cell.content_tag = .bg_color_rgb;
    rgb.cell.content = .{ .color_rgb = .{
        .r = 0xaa,
        .g = 0xbb,
        .b = 0xcc,
    } };
    rgb.cell.protected = true;

    const spacer_head = page.getRowAndCell(2, 1);
    spacer_head.cell.wide = .spacer_head;
    spacer_head.row.wrap = true;
    spacer_head.row.wrap_continuation = true;
    spacer_head.row.semantic_prompt = .prompt_continuation;

    const header: Header = .{
        .columns = 3,
        .rows = 2,
        .style_count = 2,
        .hyperlink_count = 2,
        .style_capacity = 8,
        .hyperlink_capacity_bytes = 512,
        .grapheme_capacity_bytes = 128,
        .string_capacity_bytes = 256,
    };
    try std.testing.expectEqual(header, Header.init(&page));

    // Lock the payload bytes and independently verify the counting writer sees
    // the same encoded length.
    var counter: std.Io.Writer.Discarding = .init(&.{});
    try encodePayload(&page, &counter.writer);

    var encoded: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try encodePayload(&page, &writer);

    const fixture = test_page_fixture;
    try std.testing.expectEqualStrings(fixture, writer.buffered());
    try std.testing.expectEqual(@as(u64, fixture.len), counter.count);

    // A one-byte backing buffer exercises streaming reads across every field.
    var source: std.Io.Reader = .fixed(writer.buffered());
    var read_buf: [1]u8 = undefined;
    var limited = source.limited(.unlimited, &read_buf);
    var decoded = try decodePayload(
        &limited.interface,
        std.testing.allocator,
    );
    defer decoded.deinit();

    try std.testing.expectEqual(header, Header.init(&decoded));
    try decoded.verifyIntegrity(std.testing.allocator);

    // Decoding compacts the sparse source IDs while preserving table values
    // and all cell references through the remap tables.
    var style_it = decoded.styles.iterator(decoded.memory);
    const decoded_style_a = style_it.next().?;
    try std.testing.expectEqual(@as(TerminalStyleId, 1), decoded_style_a.id);
    try std.testing.expect((TerminalStyle{
        .flags = .{ .bold = true },
    }).eql(decoded_style_a.value_ptr.*));
    const decoded_style_b = style_it.next().?;
    try std.testing.expectEqual(@as(TerminalStyleId, 2), decoded_style_b.id);
    try std.testing.expect((TerminalStyle{
        .bg_color = .{ .palette = 42 },
    }).eql(decoded_style_b.value_ptr.*));
    try std.testing.expectEqual(null, style_it.next());

    var hyperlink_it = decoded.hyperlink_set.iterator(decoded.memory);
    const decoded_link_a = hyperlink_it.next().?;
    try std.testing.expectEqual(@as(TerminalHyperlinkId, 1), decoded_link_a.id);
    const decoded_hyperlink_a = pageHyperlink(&decoded, decoded_link_a.value_ptr);
    try std.testing.expectEqualStrings("a", decoded_hyperlink_a.id.explicit);
    try std.testing.expectEqualStrings("alpha", decoded_hyperlink_a.uri);
    const decoded_link_b = hyperlink_it.next().?;
    try std.testing.expectEqual(@as(TerminalHyperlinkId, 2), decoded_link_b.id);
    const decoded_hyperlink_b = pageHyperlink(&decoded, decoded_link_b.value_ptr);
    try std.testing.expectEqual(@as(u32, 0x01020304), decoded_hyperlink_b.id.implicit);
    try std.testing.expectEqualStrings("beta", decoded_hyperlink_b.uri);
    try std.testing.expectEqual(null, hyperlink_it.next());

    const decoded_first = decoded.getRowAndCell(0, 0);
    try std.testing.expectEqual(@as(u21, 'A'), decoded_first.cell.codepoint());
    try std.testing.expectEqual(TerminalCell.Wide.wide, decoded_first.cell.wide);
    try std.testing.expect(decoded_first.cell.protected);
    try std.testing.expectEqual(
        TerminalCell.SemanticContent.prompt,
        decoded_first.cell.semantic_content,
    );
    try std.testing.expectEqual(@as(TerminalStyleId, 1), decoded_first.cell.style_id);
    try std.testing.expectEqual(
        @as(TerminalHyperlinkId, 1),
        decoded.lookupHyperlink(decoded_first.cell).?,
    );

    const decoded_second = decoded.getRowAndCell(1, 0);
    try std.testing.expectEqual(TerminalCell.Wide.spacer_tail, decoded_second.cell.wide);
    try std.testing.expectEqual(@as(TerminalStyleId, 2), decoded_second.cell.style_id);
    try std.testing.expectEqual(
        @as(TerminalHyperlinkId, 2),
        decoded.lookupHyperlink(decoded_second.cell).?,
    );

    const decoded_grapheme = decoded.getRowAndCell(0, 1);
    try std.testing.expectEqualSlices(
        u21,
        &.{ 0x0301, 0x0302 },
        decoded.lookupGrapheme(decoded_grapheme.cell).?,
    );

    const decoded_rgb = decoded.getRowAndCell(1, 1);
    try std.testing.expectEqual(TerminalCell.ContentTag.bg_color_rgb, decoded_rgb.cell.content_tag);
    try std.testing.expectEqual(
        TerminalCell.RGB{ .r = 0xaa, .g = 0xbb, .b = 0xcc },
        decoded_rgb.cell.content.color_rgb,
    );

    const decoded_spacer_head = decoded.getRowAndCell(2, 1);
    try std.testing.expectEqual(
        TerminalCell.Wide.spacer_head,
        decoded_spacer_head.cell.wide,
    );
    try std.testing.expect(decoded_spacer_head.row.wrap);
    try std.testing.expect(decoded_spacer_head.row.wrap_continuation);
    try std.testing.expectEqual(
        TerminalRow.SemanticPrompt.prompt_continuation,
        decoded_spacer_head.row.semantic_prompt,
    );

    // The first re-encode reflects compacted IDs; subsequent round trips must
    // stabilize byte-for-byte.
    var reencoded: [512]u8 = undefined;
    var rewriter: std.Io.Writer = .fixed(&reencoded);
    try encodePayload(&decoded, &rewriter);
    try std.testing.expect(!std.mem.eql(
        u8,
        writer.buffered(),
        rewriter.buffered(),
    ));

    var reencoded_reader: std.Io.Reader = .fixed(rewriter.buffered());
    var decoded_again = try decodePayload(
        &reencoded_reader,
        std.testing.allocator,
    );
    defer decoded_again.deinit();
    try decoded_again.verifyIntegrity(std.testing.allocator);

    var reencoded_again: [512]u8 = undefined;
    var rewriter_again: std.Io.Writer = .fixed(&reencoded_again);
    try encodePayload(&decoded_again, &rewriter_again);
    try std.testing.expectEqualStrings(
        rewriter.buffered(),
        rewriter_again.buffered(),
    );

    // The public codec appends one complete PAGE record after the envelope.
    var snapshot: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer snapshot.deinit();
    try envelope.encode(&snapshot.writer);
    try encode(&page, &snapshot);

    const snapshot_bytes = snapshot.written();
    try std.testing.expectEqualStrings(
        test_page_fixture,
        snapshot_bytes[envelope.encoded_len + record.Header.len ..],
    );

    var snapshot_reader: std.Io.Reader = .fixed(snapshot_bytes);
    try envelope.decode(&snapshot_reader);
    var framed_page = try decode(
        &snapshot_reader,
        std.testing.allocator,
    );
    defer framed_page.deinit();

    try std.testing.expectEqual(header, Header.init(&framed_page));
    const framed_first = framed_page.getRowAndCell(0, 0);
    try std.testing.expectEqual(@as(u21, 'A'), framed_first.cell.codepoint());
    try std.testing.expectEqual(
        TerminalCell.SemanticContent.prompt,
        framed_first.cell.semantic_content,
    );
    try std.testing.expectEqualSlices(
        u21,
        &.{ 0x0301, 0x0302 },
        framed_page.lookupGrapheme(
            framed_page.getRowAndCell(0, 1).cell,
        ).?,
    );
}

test "framed PAGE golden empty record" {
    const capacity: TerminalPageCapacity = .{
        .cols = 1,
        .rows = 1,
        .styles = 0,
        .hyperlink_bytes = 0,
        .grapheme_bytes = 0,
        .string_bytes = 0,
    };
    var page = try TerminalPage.init(capacity);
    defer page.deinit();

    var destination: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer destination.deinit();
    try encode(&page, &destination);
    try std.testing.expectEqualStrings(
        test_empty_framed_page_fixture,
        destination.written(),
    );

    var source: std.Io.Reader = .fixed(destination.written());
    var decoded = try decode(&source, std.testing.allocator);
    defer decoded.deinit();
    try std.testing.expectEqual(
        Header.init(&page),
        Header.init(&decoded),
    );
}

test "framed PAGE validates tag length checksum and exhaustion" {
    {
        // A valid non-PAGE tag is rejected before payload decoding.
        var wrong_tag = test_empty_framed_page_fixture.*;
        std.mem.writeInt(u16, wrong_tag[0..2], @intFromEnum(record.Tag.screen), .little);
        var reader: std.Io.Reader = .fixed(&wrong_tag);
        try std.testing.expectError(
            error.UnexpectedRecordTag,
            decode(&reader, std.testing.allocator),
        );
    }

    {
        // Corrupt only the stored checksum.
        var invalid_checksum = test_empty_framed_page_fixture.*;
        invalid_checksum[6] ^= 1;
        var reader: std.Io.Reader = .fixed(&invalid_checksum);
        try std.testing.expectError(
            error.InvalidChecksum,
            decode(&reader, std.testing.allocator),
        );
    }

    {
        // Mutate a cell without updating the checksum.
        var invalid_payload = test_empty_framed_page_fixture.*;
        const value_offset = record.Header.len +
            Header.len +
            1 +
            8;
        invalid_payload[value_offset] = 'A';
        var reader: std.Io.Reader = .fixed(&invalid_payload);
        try std.testing.expectError(
            error.InvalidChecksum,
            decode(&reader, std.testing.allocator),
        );
    }

    {
        // Advertise one byte less than the PAGE decoder requires.
        var short_payload = test_empty_framed_page_fixture.*;
        std.mem.writeInt(u32, short_payload[2..6], 36, .little);
        var reader: std.Io.Reader = .fixed(&short_payload);
        try std.testing.expectError(
            error.EndOfStream,
            decode(&reader, std.testing.allocator),
        );
    }

    {
        // Add a payload byte and recompute the checksum so exhaustion, rather
        // than checksum validation, is what fails.
        var trailing: [test_empty_framed_page_fixture.len + 1]u8 = undefined;
        @memcpy(
            trailing[0..test_empty_framed_page_fixture.len],
            test_empty_framed_page_fixture,
        );
        trailing[trailing.len - 1] = 0;
        std.mem.writeInt(u32, trailing[2..6], 38, .little);

        var checksum: record.Checksum = .init(.page, 38);
        try checksum.writer().writeAll(trailing[record.Header.len..]);
        std.mem.writeInt(u32, trailing[6..10], checksum.final(), .little);

        var reader: std.Io.Reader = .fixed(&trailing);
        try std.testing.expectError(
            error.PayloadNotExhausted,
            decode(&reader, std.testing.allocator),
        );
    }
}

test "framed PAGE rejects every truncation and preserves following bytes" {
    for (0..test_empty_framed_page_fixture.len) |len| {
        var reader: std.Io.Reader = .fixed(
            test_empty_framed_page_fixture[0..len],
        );
        if (decode(&reader, std.testing.allocator)) |decoded_value| {
            var unexpected = decoded_value;
            unexpected.deinit();
            return error.ExpectedDecodeFailure;
        } else |_| {}
    }

    var source: std.Io.Reader = .fixed(
        test_empty_framed_page_fixture ++ "next",
    );
    var decoded = try decode(&source, std.testing.allocator);
    defer decoded.deinit();
    try std.testing.expectEqualStrings("next", try source.take(4));
}

test "decode sparse page rejects every truncation" {
    for (0..test_page_fixture.len) |len| {
        var reader: std.Io.Reader = .fixed(test_page_fixture[0..len]);
        try std.testing.expectError(
            error.EndOfStream,
            decodePayload(&reader, std.testing.allocator),
        );
    }
}

test "decode accepts unordered sparse style IDs and rejects zero" {
    const header: Header = .{
        .columns = 1,
        .rows = 1,
        .style_count = 2,
        .hyperlink_count = 0,
        .style_capacity = 8,
        .hyperlink_capacity_bytes = 0,
        .grapheme_capacity_bytes = 0,
        .string_capacity_bytes = 0,
    };

    var descending: [
        Header.len +
            2 * (2 + style.len) +
            1 +
            16
    ]u8 = undefined;
    var descending_writer: std.Io.Writer = .fixed(&descending);
    try header.encode(&descending_writer);
    try io.writeInt(&descending_writer, TerminalStyleId, 3);
    try style.encode(.{ .flags = .{ .bold = true } }, &descending_writer);
    try io.writeInt(&descending_writer, TerminalStyleId, 2);
    try style.encode(.{ .flags = .{ .italic = true } }, &descending_writer);
    try descending_writer.writeByte(0);
    try descending_writer.splatByteAll(0, 16);

    var descending_reader: std.Io.Reader = .fixed(
        descending_writer.buffered(),
    );
    var decoded_descending = try decodePayload(
        &descending_reader,
        std.testing.allocator,
    );
    defer decoded_descending.deinit();
    try std.testing.expectEqual(@as(usize, 2), decoded_descending.styles.count());

    const one_header: Header = .{
        .columns = 1,
        .rows = 1,
        .style_count = 1,
        .hyperlink_count = 0,
        .style_capacity = 8,
        .hyperlink_capacity_bytes = 0,
        .grapheme_capacity_bytes = 0,
        .string_capacity_bytes = 0,
    };

    var zero: [Header.len + 2 + style.len]u8 = undefined;
    var zero_writer: std.Io.Writer = .fixed(&zero);
    try one_header.encode(&zero_writer);
    try io.writeInt(&zero_writer, TerminalStyleId, 0);
    try style.encode(.{ .flags = .{ .bold = true } }, &zero_writer);

    var zero_reader: std.Io.Reader = .fixed(zero_writer.buffered());
    try std.testing.expectError(
        error.InvalidStyleId,
        decodePayload(&zero_reader, std.testing.allocator),
    );
}

test "decode accepts unordered sparse hyperlink IDs" {
    const header: Header = .{
        .columns = 1,
        .rows = 1,
        .style_count = 0,
        .hyperlink_count = 2,
        .style_capacity = 0,
        .hyperlink_capacity_bytes = 512,
        .grapheme_capacity_bytes = 0,
        .string_capacity_bytes = 0,
    };

    const first: TerminalHyperlink = .{
        .id = .{ .implicit = 1 },
        .uri = "",
    };
    const second: TerminalHyperlink = .{
        .id = .{ .implicit = 2 },
        .uri = "",
    };

    var encoded: [
        Header.len +
            2 * 11 +
            1 +
            16
    ]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try header.encode(&writer);
    try io.writeInt(&writer, TerminalHyperlinkId, 3);
    try hyperlink.encode(first, &writer);
    try io.writeInt(&writer, TerminalHyperlinkId, 2);
    try hyperlink.encode(second, &writer);
    try writer.writeByte(0);
    try writer.splatByteAll(0, 16);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    var decoded = try decodePayload(
        &reader,
        std.testing.allocator,
    );
    defer decoded.deinit();
    try std.testing.expectEqual(
        @as(usize, 2),
        decoded.hyperlink_set.count(),
    );
}

test "decode defaults missing sparse cell references" {
    // An unknown style ID falls back to the default style.
    const style_header: Header = .{
        .columns = 1,
        .rows = 1,
        .style_count = 0,
        .hyperlink_count = 0,
        .style_capacity = 8,
        .hyperlink_capacity_bytes = 0,
        .grapheme_capacity_bytes = 0,
        .string_capacity_bytes = 0,
    };

    var style_encoded: [Header.len + 1 + 16]u8 = undefined;
    var style_writer: std.Io.Writer = .fixed(&style_encoded);
    try style_header.encode(&style_writer);
    try style_writer.writeByte(0);
    try style_writer.writeAll(&.{ 0, 0, 0, 0 });
    try io.writeInt(&style_writer, TerminalStyleId, 1);
    try io.writeInt(&style_writer, TerminalHyperlinkId, 0);
    try io.writeInt(&style_writer, u32, 0);
    try io.writeInt(&style_writer, u32, 0);

    var style_reader: std.Io.Reader = .fixed(style_writer.buffered());
    var style_page = try decodePayload(
        &style_reader,
        std.testing.allocator,
    );
    defer style_page.deinit();
    try std.testing.expectEqual(
        @as(TerminalStyleId, 0),
        style_page.getRowAndCell(0, 0).cell.style_id,
    );

    // An unknown hyperlink ID likewise falls back to no hyperlink.
    const hyperlink_header: Header = .{
        .columns = 1,
        .rows = 1,
        .style_count = 0,
        .hyperlink_count = 0,
        .style_capacity = 0,
        .hyperlink_capacity_bytes = 512,
        .grapheme_capacity_bytes = 0,
        .string_capacity_bytes = 0,
    };

    var hyperlink_encoded: [Header.len + 1 + 16]u8 = undefined;
    var hyperlink_writer: std.Io.Writer = .fixed(&hyperlink_encoded);
    try hyperlink_header.encode(&hyperlink_writer);
    try hyperlink_writer.writeByte(0);
    try hyperlink_writer.writeAll(&.{ 0, 0, 0, 0 });
    try io.writeInt(&hyperlink_writer, TerminalStyleId, 0);
    try io.writeInt(&hyperlink_writer, TerminalHyperlinkId, 1);
    try io.writeInt(&hyperlink_writer, u32, 0);
    try io.writeInt(&hyperlink_writer, u32, 0);

    var hyperlink_reader: std.Io.Reader = .fixed(
        hyperlink_writer.buffered(),
    );
    var hyperlink_page = try decodePayload(
        &hyperlink_reader,
        std.testing.allocator,
    );
    defer hyperlink_page.deinit();
    const hyperlink_cell = hyperlink_page.getRowAndCell(0, 0).cell;
    try std.testing.expect(!hyperlink_cell.hyperlink);
    try std.testing.expectEqual(
        null,
        hyperlink_page.lookupHyperlink(hyperlink_cell),
    );
}

test "decode rejects undefined row and cell values" {
    const header: Header = .{
        .columns = 1,
        .rows = 1,
        .style_count = 0,
        .hyperlink_count = 0,
        .style_capacity = 0,
        .hyperlink_capacity_bytes = 0,
        .grapheme_capacity_bytes = 0,
        .string_capacity_bytes = 0,
    };

    var invalid_row: [Header.len + 1]u8 = undefined;
    var row_writer: std.Io.Writer = .fixed(&invalid_row);
    try header.encode(&row_writer);
    try row_writer.writeByte(0x10);

    var row_reader: std.Io.Reader = .fixed(row_writer.buffered());
    try std.testing.expectError(
        error.InvalidRow,
        decodePayload(&row_reader, std.testing.allocator),
    );

    var invalid_cell: [Header.len + 2]u8 = undefined;
    var cell_writer: std.Io.Writer = .fixed(&invalid_cell);
    try header.encode(&cell_writer);
    try cell_writer.writeByte(0);
    try cell_writer.writeByte(3);

    var cell_reader: std.Io.Reader = .fixed(cell_writer.buffered());
    try std.testing.expectError(
        error.InvalidCell,
        decodePayload(&cell_reader, std.testing.allocator),
    );

    var invalid_codepoint: [Header.len + 1 + 16]u8 = undefined;
    var codepoint_writer: std.Io.Writer = .fixed(&invalid_codepoint);
    try header.encode(&codepoint_writer);
    try codepoint_writer.writeByte(0);
    try codepoint_writer.writeAll(&.{ 0, 0, 0, 0 });
    try io.writeInt(&codepoint_writer, TerminalStyleId, 0);
    try io.writeInt(&codepoint_writer, TerminalHyperlinkId, 0);
    try io.writeInt(&codepoint_writer, u32, 0xD800);
    try io.writeInt(&codepoint_writer, u32, 0);

    var codepoint_reader: std.Io.Reader = .fixed(
        codepoint_writer.buffered(),
    );
    try std.testing.expectError(
        error.InvalidCodepoint,
        decodePayload(&codepoint_reader, std.testing.allocator),
    );

    var invalid_color: [Header.len + 1 + 16]u8 = undefined;
    var color_writer: std.Io.Writer = .fixed(&invalid_color);
    try header.encode(&color_writer);
    try color_writer.writeByte(0);
    try color_writer.writeAll(&.{ 1, 0, 0, 0 });
    try io.writeInt(&color_writer, TerminalStyleId, 0);
    try io.writeInt(&color_writer, TerminalHyperlinkId, 0);
    try io.writeInt(&color_writer, u32, 0x100);
    try io.writeInt(&color_writer, u32, 0);

    var color_reader: std.Io.Reader = .fixed(color_writer.buffered());
    try std.testing.expectError(
        error.InvalidColor,
        decodePayload(&color_reader, std.testing.allocator),
    );
}

test "decode validates dimensions and native table capacities" {
    const cases = .{
        .{
            .expected = error.InvalidDimensions,
            .header = Header{
                .columns = 0,
                .rows = 24,
                .style_count = 0,
                .hyperlink_count = 0,
                .style_capacity = 0,
                .hyperlink_capacity_bytes = 0,
                .grapheme_capacity_bytes = 0,
                .string_capacity_bytes = 0,
            },
        },
        .{
            .expected = error.InvalidDimensions,
            .header = Header{
                .columns = 80,
                .rows = 0,
                .style_count = 0,
                .hyperlink_count = 0,
                .style_capacity = 0,
                .hyperlink_capacity_bytes = 0,
                .grapheme_capacity_bytes = 0,
                .string_capacity_bytes = 0,
            },
        },
        .{
            .expected = error.InvalidStyleCapacity,
            .header = Header{
                .columns = 80,
                .rows = 24,
                .style_count = 1,
                .hyperlink_count = 0,
                .style_capacity = 0,
                .hyperlink_capacity_bytes = 0,
                .grapheme_capacity_bytes = 0,
                .string_capacity_bytes = 0,
            },
        },
        .{
            .expected = error.InvalidHyperlinkCapacity,
            .header = Header{
                .columns = 80,
                .rows = 24,
                .style_count = 0,
                .hyperlink_count = 1,
                .style_capacity = 0,
                .hyperlink_capacity_bytes = 0,
                .grapheme_capacity_bytes = 0,
                .string_capacity_bytes = 0,
            },
        },
    };

    inline for (cases) |case| {
        var encoded: [Header.len]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&encoded);
        try case.header.encode(&writer);

        var reader: std.Io.Reader = .fixed(writer.buffered());
        try std.testing.expectError(
            case.expected,
            decodePayload(&reader, std.testing.allocator),
        );
    }
}

test "decode rejects duplicate and default style entries" {
    const header: Header = .{
        .columns = 80,
        .rows = 24,
        .style_count = 2,
        .hyperlink_count = 0,
        .style_capacity = 16,
        .hyperlink_capacity_bytes = 512,
        .grapheme_capacity_bytes = 0,
        .string_capacity_bytes = 256,
    };
    const duplicate_style: TerminalStyle = .{
        .flags = .{ .bold = true },
    };

    var encoded: [Header.len + 2 * (2 + style.len)]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try header.encode(&writer);
    try io.writeInt(&writer, TerminalStyleId, 1);
    try style.encode(duplicate_style, &writer);
    try io.writeInt(&writer, TerminalStyleId, 3);
    try style.encode(duplicate_style, &writer);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    try std.testing.expectError(
        error.DuplicateStyle,
        decodePayload(&reader, std.testing.allocator),
    );

    const default_header: Header = .{
        .columns = 80,
        .rows = 24,
        .style_count = 1,
        .hyperlink_count = 0,
        .style_capacity = 16,
        .hyperlink_capacity_bytes = 0,
        .grapheme_capacity_bytes = 0,
        .string_capacity_bytes = 0,
    };
    var default_encoded: [Header.len + 2 + style.len]u8 = undefined;
    var default_writer: std.Io.Writer = .fixed(&default_encoded);
    try default_header.encode(&default_writer);
    try io.writeInt(&default_writer, TerminalStyleId, 1);
    try style.encode(.{}, &default_writer);

    var default_reader: std.Io.Reader = .fixed(default_writer.buffered());
    try std.testing.expectError(
        error.DefaultStyle,
        decodePayload(&default_reader, std.testing.allocator),
    );
}

test "decode rejects duplicate hyperlinks with empty strings" {
    const header: Header = .{
        .columns = 1,
        .rows = 1,
        .style_count = 0,
        .hyperlink_count = 2,
        .style_capacity = 0,
        .hyperlink_capacity_bytes = 512,
        .grapheme_capacity_bytes = 0,
        .string_capacity_bytes = 0,
    };
    const duplicate: TerminalHyperlink = .{
        .id = .{ .explicit = "" },
        .uri = "",
    };

    var encoded: [Header.len + 22]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try header.encode(&writer);
    try io.writeInt(&writer, TerminalHyperlinkId, 1);
    try hyperlink.encode(duplicate, &writer);
    try io.writeInt(&writer, TerminalHyperlinkId, 3);
    try hyperlink.encode(duplicate, &writer);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    try std.testing.expectError(
        error.DuplicateHyperlink,
        decodePayload(&reader, std.testing.allocator),
    );
}
