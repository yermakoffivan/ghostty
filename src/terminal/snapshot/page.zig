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
//! The default style and absence of a hyperlink are implicit at wire
//! index zero and are not included in these counts. Encoded table entries
//! receive one-based wire indexes in their encoded order.
//!
//! The final four fields are allocation hints copied from the source page.
//! These represent upper limits on what this page might contain. A decoder
//! can optionally choose to use this for preallocation or it can ignore
//! and decode and allocate dynamically.
//!
//! ### Payload
//!
//! This is still a work-in-progress. The current implementation encodes and
//! decodes the header, style table, and hyperlink table only. It does not yet
//! produce or consume a complete PAGE payload.
//!
//! Following the header, data is tightly packed in the following order:
//! styles, hyperlinks, cells. TODO!

const std = @import("std");
const hyperlink = @import("hyperlink.zig");
const io = @import("io.zig");
const style = @import("style.zig");
const terminal_hyperlink = @import("../hyperlink.zig");
const terminal_page = @import("../page.zig");
const terminal_style = @import("../style.zig");

// Frequent constants we use
const TerminalHyperlink = terminal_hyperlink.Hyperlink;
const TerminalHyperlinkPageEntry = terminal_hyperlink.PageEntry;
const TerminalHyperlinkSet = terminal_hyperlink.Set;
const TerminalPage = terminal_page.Page;
const TerminalPageCapacity = terminal_page.Capacity;
const TerminalStyle = terminal_style.Style;
const TerminalStyleId = terminal_style.Id;
const TerminalStyleSet = terminal_style.Set;

/// Errors possible while encoding the native PAGE prefix.
pub const EncodeError = hyperlink.EncodeError;

/// Errors possible while decoding the native PAGE prefix.
pub const DecodeError = style.DecodeError ||
    Header.CapacityError ||
    error{
        /// The hyperlink kind is not defined by snapshot version 0.
        InvalidKind,

        /// The advertised string capacity cannot hold the encoded hyperlinks.
        InvalidStringCapacity,

        /// A non-default style was encoded more than once.
        DuplicateStyle,

        /// A hyperlink was encoded more than once.
        DuplicateHyperlink,

        /// The default style cannot appear in the non-default style table.
        DefaultStyle,

        /// Native page backing memory could not be allocated.
        OutOfMemory,
    };

/// Encode the PAGE header and lookup tables directly from a native page.
///
/// Only the currently implemented PAGE prefix is written. Rows and cells will
/// be appended by a later increment. The page is iterated in place and no
/// temporary storage is allocated or retained.
pub fn encode(
    page: *const TerminalPage,
    writer: *std.Io.Writer,
) EncodeError!void {
    // Write header
    try Header.init(page).encode(writer);

    // Packed styles
    var style_it = page.styles.iterator(page.memory);
    while (style_it.next()) |entry| {
        try style.encode(entry.value_ptr.*, writer);
    }

    // Packed hyperlinks
    var hyperlink_it = page.hyperlink_set.iterator(page.memory);
    while (hyperlink_it.next()) |entry| {
        try hyperlink.encode(pageHyperlink(page, entry.value_ptr), writer);
    }
}

/// Decode the PAGE header and lookup tables directly into a native page.
///
/// The fixed header is validated before allocating the page. Style entries
/// are inserted directly into the page style set, while hyperlink strings are
/// read into the page string allocator before their native entries are
/// inserted. No caller-owned table or string buffers are required.
///
/// Only the currently implemented PAGE prefix is consumed. Rows and cells
/// will be decoded by a later increment.
pub fn decode(
    reader: *std.Io.Reader,
) DecodeError!TerminalPage {
    // Decode the header, validate capacities, init page
    const header = try Header.decode(reader);
    const capacity = try header.pageCapacity();
    var page = TerminalPage.init(capacity) catch
        return error.OutOfMemory;
    errdefer page.deinit();

    // Styles
    for (0..header.style_count) |wire_index| {
        const value = try style.decode(reader);
        if (value.default()) return error.DefaultStyle;

        const native_id = page.styles.add(
            page.memory,
            value,
        ) catch return error.InvalidStyleCapacity;
        if (native_id != wire_index + 1) return error.DuplicateStyle;
    }

    // Hyperlinks
    for (0..header.hyperlink_count) |wire_index| {
        const native_id = hyperlink.decodePage(
            &page,
            reader,
        ) catch |err| switch (err) {
            error.StringsOutOfMemory => return error.InvalidStringCapacity,
            error.SetOutOfMemory,
            error.SetNeedsRehash,
            => return error.InvalidHyperlinkCapacity,
            else => return err,
        };
        if (native_id != wire_index + 1) return error.DuplicateHyperlink;
    }

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

test "encode native page lookup tables" {
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

    const grapheme = page.getRowAndCell(0, 1);
    grapheme.cell.* = .init('x');
    try page.setGraphemes(
        grapheme.row,
        grapheme.cell,
        &.{ 0x0301, 0x0302 },
    );

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

    var counter: std.Io.Writer.Discarding = .init(&.{});
    try encode(&page, &counter.writer);

    var encoded: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try encode(&page, &writer);

    const fixture =
        "\x03\x00\x02\x00\x02\x00\x02\x00" ++
        "\x08\x00\x00\x02\x80\x00\x00\x00" ++
        "\x00\x01\x00\x00" ++
        "\x00\x00\x00\x00\x00\x00\x00\x00" ++
        "\x00\x00\x00\x00\x01\x00\x00\x00" ++
        "\x00\x00\x00\x00\x01\x2a\x00\x00" ++
        "\x00\x00\x00\x00\x00\x00\x00\x00" ++
        "\x02\x01\x00\x00\x00a\x05\x00\x00\x00alpha" ++
        "\x01\x04\x03\x02\x01\x04\x00\x00\x00beta";
    try std.testing.expectEqualStrings(fixture, writer.buffered());
    try std.testing.expectEqual(@as(u64, fixture.len), counter.count);
}

test "decode lookup tables directly into a native page" {
    const header: Header = .{
        .columns = 80,
        .rows = 24,
        .style_count = 2,
        .hyperlink_count = 2,
        .style_capacity = 16,
        .hyperlink_capacity_bytes = 512,
        .grapheme_capacity_bytes = 128,
        .string_capacity_bytes = 256,
    };

    const fixture =
        "\x50\x00\x18\x00\x02\x00\x02\x00" ++
        "\x10\x00\x00\x02\x80\x00\x00\x00" ++
        "\x00\x01\x00\x00" ++
        "\x01\x2a\x00\x00\x00\x00\x00\x00" ++
        "\x00\x00\x00\x00\x01\x00\x00\x00" ++
        "\x00\x00\x00\x00\x02\xaa\xbb\xcc" ++
        "\x00\x00\x00\x00\x00\x02\x00\x00" ++
        "\x01\x04\x03\x02\x01\x03\x00\x00\x00uri" ++
        "\x02\x02\x00\x00\x00id\x03\x00\x00\x00url";

    var source: std.Io.Reader = .fixed(fixture);
    var read_buf: [1]u8 = undefined;
    var limited = source.limited(.unlimited, &read_buf);
    var decoded = try decode(&limited.interface);
    defer decoded.deinit();

    try std.testing.expectEqual(header, Header.init(&decoded));
    try decoded.verifyIntegrity(std.testing.allocator);

    var style_it = decoded.styles.iterator(decoded.memory);
    const style_a = style_it.next().?;
    try std.testing.expectEqual(@as(TerminalStyleId, 1), style_a.id);
    try std.testing.expect((TerminalStyle{
        .fg_color = .{ .palette = 42 },
        .flags = .{ .bold = true },
    }).eql(style_a.value_ptr.*));
    const style_b = style_it.next().?;
    try std.testing.expectEqual(@as(TerminalStyleId, 2), style_b.id);
    try std.testing.expect((TerminalStyle{
        .bg_color = .{ .rgb = .{
            .r = 0xaa,
            .g = 0xbb,
            .b = 0xcc,
        } },
        .flags = .{ .underline = .double },
    }).eql(style_b.value_ptr.*));
    try std.testing.expectEqual(null, style_it.next());

    var hyperlink_it = decoded.hyperlink_set.iterator(decoded.memory);
    const hyperlink_a = pageHyperlink(
        &decoded,
        hyperlink_it.next().?.value_ptr,
    );
    try std.testing.expectEqual(
        @as(u32, 0x01020304),
        hyperlink_a.id.implicit,
    );
    try std.testing.expectEqualStrings("uri", hyperlink_a.uri);
    const hyperlink_b = pageHyperlink(
        &decoded,
        hyperlink_it.next().?.value_ptr,
    );
    try std.testing.expectEqualStrings("id", hyperlink_b.id.explicit);
    try std.testing.expectEqualStrings("url", hyperlink_b.uri);
    try std.testing.expectEqual(null, hyperlink_it.next());

    var reencoded: [fixture.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&reencoded);
    try encode(&decoded, &writer);
    try std.testing.expectEqualStrings(fixture, writer.buffered());
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
        try std.testing.expectError(case.expected, decode(&reader));
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

    var encoded: [Header.len + 2 * style.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try header.encode(&writer);
    try style.encode(duplicate_style, &writer);
    try style.encode(duplicate_style, &writer);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    try std.testing.expectError(error.DuplicateStyle, decode(&reader));

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
    var default_encoded: [Header.len + style.len]u8 = undefined;
    var default_writer: std.Io.Writer = .fixed(&default_encoded);
    try default_header.encode(&default_writer);
    try style.encode(.{}, &default_writer);

    var default_reader: std.Io.Reader = .fixed(default_writer.buffered());
    try std.testing.expectError(error.DefaultStyle, decode(&default_reader));
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

    var encoded: [Header.len + 18]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try header.encode(&writer);
    try hyperlink.encode(duplicate, &writer);
    try hyperlink.encode(duplicate, &writer);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    try std.testing.expectError(error.DuplicateHyperlink, decode(&reader));
}

test "decode reads hyperlink strings into page storage" {
    const link: TerminalHyperlink = .{
        .id = .{ .explicit = "id" },
        .uri = "uri",
    };
    const hyperlink_capacity: u16 = @intCast(
        TerminalHyperlinkSet.capacityForCount(1) *
            @sizeOf(TerminalHyperlinkSet.Item),
    );
    const header: Header = .{
        .columns = 1,
        .rows = 1,
        .style_count = 0,
        .hyperlink_count = 1,
        .style_capacity = 0,
        .hyperlink_capacity_bytes = hyperlink_capacity,
        .grapheme_capacity_bytes = 0,
        .string_capacity_bytes = 0,
    };

    var encoded: [Header.len + 14]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try header.encode(&writer);
    try hyperlink.encode(link, &writer);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    try std.testing.expectError(
        error.InvalidStringCapacity,
        decode(&reader),
    );
}
