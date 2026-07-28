//! Grid (rows and cells) encoding.
//!
//! A grid contains the rows and cells of a terminal page. Its dimensions are
//! supplied by the containing record rather than repeated here. The encoder
//! writes exactly `rows` row records, and every row contains exactly `columns`
//! cell records.
//!
//! All records are tightly packed with no padding between them. All integers
//! are unsigned and little-endian.
//!
//! ## Row
//!
//! Each row has the following format:
//!
//! | Offset | Size     | Field                       |
//! | -----: | -------: | :-------------------------- |
//! |      0 |        1 | Row flags                   |
//! |      1 | variable | Exactly `columns` cells     |
//!
//! Cells are encoded consecutively. Since cells may contain a variable number
//! of grapheme codepoints, the next row begins immediately after the final
//! cell and its grapheme codepoints.
//!
//! The row flag byte has the following format:
//!
//! | Bits | Field                     |
//! | ---: | :------------------------ |
//! |    0 | Wrap                      |
//! |    1 | Wrap continuation         |
//! |  2-3 | Semantic prompt           |
//! |  4-7 | Reserved, zero            |
//!
//! Semantic prompt values are:
//!
//! | Value | Meaning             |
//! | ----: | :------------------ |
//! |     0 | None                |
//! |     1 | Prompt              |
//! |     2 | Prompt continuation |
//!
//! Value 3 is invalid in snapshot version 1.
//!
//! ## Cell
//!
//! Each cell has the following format:
//!
//! | Offset | Size      | Field                         |
//! | -----: | --------: | :---------------------------- |
//! |      0 |         1 | Content kind                  |
//! |      1 |         1 | Width kind                    |
//! |      2 |         1 | Protected and semantic flags  |
//! |      3 |         1 | Reserved, zero                |
//! |      4 |         2 | Style ID                      |
//! |      6 |         2 | Hyperlink ID                  |
//! |      8 |         4 | Codepoint or packed color     |
//! |     12 |         4 | Grapheme suffix count         |
//! |     16 | 4 * count | Grapheme suffix codepoints    |
//!
//! Content kinds are:
//!
//! | Value | Meaning            |
//! | ----: | :----------------- |
//! |     0 | Codepoint          |
//! |     1 | Palette background |
//! |     2 | RGB background     |
//!
//! For codepoint content, the value is a Unicode scalar encoded as a `u32`.
//! For a palette background, the low byte is the palette index and the other
//! three bytes are zero. For an RGB background, the low three bytes are red,
//! green, and blue, and the high byte is zero.
//!
//! Width kinds are:
//!
//! | Value | Meaning     |
//! | ----: | :---------- |
//! |     0 | Narrow      |
//! |     1 | Wide        |
//! |     2 | Spacer tail |
//! |     3 | Spacer head |
//!
//! The cell flag byte has the following format:
//!
//! | Bits | Field             |
//! | ---: | :---------------- |
//! |    0 | Protected         |
//! |  1-2 | Semantic content  |
//! |  3-7 | Reserved, zero    |
//!
//! Semantic content values are:
//!
//! | Value | Meaning |
//! | ----: | :------ |
//! |     0 | Output  |
//! |     1 | Input   |
//! |     2 | Prompt  |
//!
//! Value 3 is invalid in snapshot version 1.
//!
//! Style and hyperlink ID zero mean no style and no hyperlink. Other IDs
//! refer to entries in the containing record's separate style and hyperlink
//! tables.
//!
//! Grapheme suffixes are valid only for codepoint content. Each suffix is a
//! Unicode scalar encoded as a `u32`. A nonzero suffix count requires a
//! nonzero base codepoint.

const std = @import("std");
const io = @import("io.zig");
const kitty = @import("../kitty.zig");
const terminal_hyperlink = @import("../hyperlink.zig");
const terminal_page = @import("../page.zig");
const terminal_style = @import("../style.zig");

const TerminalCell = terminal_page.Cell;
const TerminalHyperlinkId = terminal_hyperlink.Id;
const TerminalPage = terminal_page.Page;
const TerminalRow = terminal_page.Row;
const TerminalStyleId = terminal_style.Id;

/// Maps encoded style table IDs to IDs assigned by the destination page.
///
/// Build this by inserting each decoded style into the page, then recording
/// the encoded ID and the ID returned by the page's style set. Style ID zero is
/// implicit and does not need an entry.
pub const StyleRemap = std.AutoHashMap(TerminalStyleId, TerminalStyleId);

/// Maps encoded hyperlink table IDs to IDs assigned by the destination page.
///
/// Build this by inserting each decoded hyperlink into the page, then
/// recording the encoded ID and the ID returned by the page's hyperlink set.
/// Hyperlink ID zero is implicit and does not need an entry.
pub const HyperlinkRemap = std.AutoHashMap(TerminalHyperlinkId, TerminalHyperlinkId);

pub const EncodeError = std.Io.Writer.Error;

/// Encode every row and cell directly from a page.
pub fn encode(
    page: *const TerminalPage,
    writer: *std.Io.Writer,
) EncodeError!void {
    // Encoding assumes a structurally valid page. This assertion performs the
    // comprehensive check in slow-safety builds without adding an allocator to
    // the encoder API.
    page.assertIntegrity();

    for (0..page.size.rows) |y| {
        // Row header
        const row = page.getRow(y);
        const row_header: RowHeader = .{
            .wrap = row.wrap,
            .wrap_continuation = row.wrap_continuation,
            .semantic_prompt = switch (row.semantic_prompt) {
                .none => .none,
                .prompt => .prompt,
                .prompt_continuation => .prompt_continuation,
            },
        };
        try writer.writeByte(@bitCast(row_header));

        // Cells
        const cells = page.getCells(row);
        for (cells) |*cell| {
            const graphemes: []const u21 = if (cell.hasGrapheme())
                page.lookupGrapheme(cell) orelse unreachable
            else
                &.{};

            // The page has two codepoint tags depending on whether suffixes
            // exist, but the wire represents both with one content kind.
            const kind: CellHeader.Kind = switch (cell.content_tag) {
                .codepoint, .codepoint_grapheme => .codepoint,
                .bg_color_palette => .bg_color_palette,
                .bg_color_rgb => .bg_color_rgb,
            };
            const value: CellHeader.Value = switch (kind) {
                .codepoint => .{
                    .codepoint = cell.content.codepoint.data,
                },
                .bg_color_palette => .{ .bg_color_palette = .{
                    .index = cell.content.color_palette.data,
                } },
                .bg_color_rgb => .{ .bg_color_rgb = .{
                    .r = cell.content.color_rgb.r,
                    .g = cell.content.color_rgb.g,
                    .b = cell.content.color_rgb.b,
                } },
            };

            const style_id = cell.style_id;
            const hyperlink_id: TerminalHyperlinkId = if (cell.hyperlink)
                page.lookupHyperlink(cell) orelse unreachable
            else
                0;

            const header: CellHeader = .{
                .content_kind = kind,
                .width = cell.wide,
                .protected = cell.protected,
                .semantic_content = cell.semantic_content,
                .style_id = style_id,
                .hyperlink_id = hyperlink_id,
                .value = value,
                .grapheme_count = @intCast(graphemes.len),
            };
            try header.encode(writer);
            for (graphemes) |suffix| try io.writeInt(
                writer,
                u32,
                suffix,
            );
        }
    }
}

pub const DecodeError = CellHeader.DecodeError || error{
    /// A row contains undefined flag values.
    InvalidRow,

    /// A cell contains an undefined kind, width, flag, or reserved value.
    InvalidCell,

    /// A grapheme suffix is invalid or attached to non-codepoint content.
    InvalidGrapheme,

    /// The advertised grapheme capacity cannot hold the encoded suffixes.
    InvalidGraphemeCapacity,

    /// A codepoint is not a Unicode scalar value.
    InvalidCodepoint,

    /// A packed background color has nonzero reserved bytes.
    InvalidColor,

    /// Wide and spacer cells do not form a valid row.
    InvalidWideCell,

    /// The hyperlink map cannot hold the encoded cell references.
    InvalidHyperlinkCapacity,

    /// PAGE records do not support Kitty graphics placeholders.
    UnsupportedKittyGraphics,
};

/// Decode every row and cell directly into an initialized, empty page.
///
/// The grid does not encode dimensions, so `page` must already have the exact
/// row and column count expected by the containing record. This function reads
/// exactly `page.size.rows` rows with `page.size.cols` cells each. The page
/// must also have enough grapheme and hyperlink-map capacity for the decoded
/// contents.
///
/// Style and hyperlink table entries must be inserted into `page` before
/// calling this function. As each table entry is inserted, the caller records
/// its encoded ID and page-assigned ID in `style_remap` or `hyperlink_remap`.
/// ID zero always means the default style or no hyperlink. A nonzero ID missing
/// from its remap is also treated as zero so unknown table references do not
/// prevent the rest of the grid from decoding.
pub fn decode(
    page: *TerminalPage,
    reader: *std.Io.Reader,
    style_remap: *const StyleRemap,
    hyperlink_remap: *const HyperlinkRemap,
) DecodeError!void {
    for (0..page.size.rows) |y| {
        const row_header: RowHeader = @bitCast(try reader.takeByte());
        if (row_header._padding != 0) return error.InvalidRow;
        const semantic_prompt: TerminalRow.SemanticPrompt =
            switch (row_header.semantic_prompt) {
                .none => .none,
                .prompt => .prompt,
                .prompt_continuation => .prompt_continuation,
                .invalid => return error.InvalidRow,
            };

        const row = page.getRow(y);
        row.wrap = row_header.wrap;
        row.wrap_continuation = row_header.wrap_continuation;
        row.semantic_prompt = semantic_prompt;

        const cells = page.getCells(row);
        for (cells, 0..) |*cell, x| {
            const header = try CellHeader.decode(reader);

            // IDs belong to the encoded page. Translate them to IDs assigned
            // by the destination page before storing them on cells.
            const encoded_style_id = header.style_id;
            const style_id = if (encoded_style_id == 0)
                0
            else
                style_remap.get(encoded_style_id) orelse 0;

            const encoded_hyperlink_id = header.hyperlink_id;
            const hyperlink_id = if (encoded_hyperlink_id == 0)
                0
            else
                hyperlink_remap.get(encoded_hyperlink_id) orelse 0;

            cell.* = .init(0);
            switch (header.content_kind) {
                .codepoint => {
                    const cp = std.math.cast(u21, header.value.codepoint) orelse
                        return error.InvalidCodepoint;
                    if (cp > 0x10FFFF or
                        (cp >= 0xD800 and cp <= 0xDFFF))
                    {
                        return error.InvalidCodepoint;
                    }
                    if (cp == kitty.graphics.unicode.placeholder) {
                        return error.UnsupportedKittyGraphics;
                    }
                    if (header.grapheme_count > 0 and cp == 0) {
                        return error.InvalidGrapheme;
                    }
                    cell.content = .{ .codepoint = .{ .data = cp } };
                },
                .bg_color_palette => {
                    const palette = header.value.bg_color_palette;
                    if (palette._padding != 0) return error.InvalidColor;
                    if (header.grapheme_count != 0) {
                        return error.InvalidGrapheme;
                    }
                    cell.content_tag = .bg_color_palette;
                    cell.content = .{
                        .color_palette = .{ .data = palette.index },
                    };
                },
                .bg_color_rgb => {
                    const rgb = header.value.bg_color_rgb;
                    if (rgb._padding != 0) return error.InvalidColor;
                    if (header.grapheme_count != 0) {
                        return error.InvalidGrapheme;
                    }
                    cell.content_tag = .bg_color_rgb;
                    cell.content = .{ .color_rgb = .{
                        .r = rgb.r,
                        .g = rgb.g,
                        .b = rgb.b,
                    } };
                },
            }

            cell.wide = header.width;
            cell.protected = header.protected;
            cell.semantic_content = header.semantic_content;

            if (style_id != 0) {
                // The table owns one reference and each decoded cell owns one
                // additional reference.
                page.styles.use(page.memory, style_id);
                cell.style_id = style_id;
                row.styled = true;
            }

            if (hyperlink_id != 0) {
                // setHyperlink records the cell mapping but intentionally does
                // not increment the set's reference count.
                page.hyperlink_set.use(page.memory, hyperlink_id);
                page.setHyperlink(row, cell, hyperlink_id) catch
                    return error.InvalidHyperlinkCapacity;
            }

            // Append directly into page-owned grapheme storage so no
            // intermediate suffix buffer is needed.
            for (0..header.grapheme_count) |_| {
                const suffix_raw = try io.readInt(reader, u32);
                const suffix = std.math.cast(u21, suffix_raw) orelse
                    return error.InvalidCodepoint;
                if (suffix > 0x10FFFF or
                    (suffix >= 0xD800 and suffix <= 0xDFFF))
                {
                    return error.InvalidCodepoint;
                }
                if (suffix == kitty.graphics.unicode.placeholder) {
                    return error.UnsupportedKittyGraphics;
                }
                page.appendGrapheme(row, cell, suffix) catch
                    return error.InvalidGraphemeCapacity;
            }

            switch (header.width) {
                .narrow, .wide => {},
                .spacer_tail => if (x == 0 or
                    cells[x - 1].wide != .wide)
                {
                    return error.InvalidWideCell;
                },
                .spacer_head => if (x + 1 != cells.len or !row.wrap) {
                    return error.InvalidWideCell;
                },
            }
        }
    }
}

/// The header before every row.
const RowHeader = packed struct(u8) {
    wrap: bool = false,
    wrap_continuation: bool = false,
    semantic_prompt: SemanticPrompt = .none,
    _padding: u4 = 0,

    const SemanticPrompt = enum(u2) {
        none = 0,
        prompt = 1,
        prompt_continuation = 2,
        invalid = 3,
    };
};

/// The fixed fields that precede a cell's grapheme suffix codepoints.
const CellHeader = struct {
    /// Number of bytes written by `encode`, calculated using the encoder itself
    /// so this remains synchronized with the field-by-field wire format.
    pub const len = computeLen();

    comptime {
        // This size is part of the wire format. If it changes, the snapshot
        // version and golden fixtures must also change.
        std.debug.assert(len == 16);
    }

    /// Interpretation of `value`.
    content_kind: Kind = .codepoint,

    /// Display width and spacer role of the cell.
    width: TerminalCell.Wide = .narrow,

    /// Whether selective erase operations protect the cell.
    protected: bool = false,

    /// Semantic role assigned by shell integration.
    semantic_content: TerminalCell.SemanticContent = .output,

    /// ID in the encoded page's style table, or zero for the default style.
    style_id: TerminalStyleId = 0,

    /// ID in the encoded page's hyperlink table, or zero for no hyperlink.
    hyperlink_id: TerminalHyperlinkId = 0,

    /// Codepoint or packed background color selected by `content_kind`.
    value: Value = .{ .codepoint = 0 },

    /// Number of grapheme suffix codepoints immediately following the header.
    grapheme_count: u32 = 0,

    /// Errors possible while decoding a fixed cell header.
    pub const DecodeError = std.Io.Reader.Error || error{InvalidCell};

    /// Encode the fixed cell header.
    pub fn encode(
        self: CellHeader,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        const semantic_content: Flags.SemanticContent = switch (self.semantic_content) {
            .output => .output,
            .input => .input,
            .prompt => .prompt,
        };
        const flags: Flags = .{
            .protected = self.protected,
            .semantic_content = semantic_content,
        };

        //  0       1       2       3       4        6        8        12       16
        //  +-------+-------+-------+-------+--------+--------+--------+--------+
        //  | kind  | width | flags | zero  | style  | link   | value  | count  |
        //  | u8    | u8    | u8    | u8    | u16 LE | u16 LE | u32 LE | u32 LE |
        //  +-------+-------+-------+-------+--------+--------+--------+--------+
        try writer.writeByte(@intFromEnum(self.content_kind));
        try writer.writeByte(@intFromEnum(self.width));
        try writer.writeByte(@bitCast(flags));
        try writer.writeByte(0);
        try io.writeInt(writer, TerminalStyleId, self.style_id);
        try io.writeInt(writer, TerminalHyperlinkId, self.hyperlink_id);
        try io.writeInt(writer, u32, @bitCast(self.value));
        try io.writeInt(writer, u32, self.grapheme_count);
    }

    /// Decode and validate the fixed cell header.
    pub fn decode(reader: *std.Io.Reader) CellHeader.DecodeError!CellHeader {
        const content_kind = std.enums.fromInt(
            Kind,
            try reader.takeByte(),
        ) orelse return error.InvalidCell;

        const width = std.enums.fromInt(
            TerminalCell.Wide,
            try reader.takeByte(),
        ) orelse return error.InvalidCell;

        const flags: Flags = @bitCast(try reader.takeByte());
        if (flags._padding != 0) return error.InvalidCell;
        const semantic_content: TerminalCell.SemanticContent = switch (flags.semantic_content) {
            .output => .output,
            .input => .input,
            .prompt => .prompt,
            .invalid => return error.InvalidCell,
        };

        // This byte is reserved so the IDs and content value remain naturally
        // aligned within the fixed cell header.
        if (try reader.takeByte() != 0) return error.InvalidCell;

        return .{
            .content_kind = content_kind,
            .width = width,
            .protected = flags.protected,
            .semantic_content = semantic_content,
            .style_id = try io.readInt(reader, TerminalStyleId),
            .hyperlink_id = try io.readInt(reader, TerminalHyperlinkId),
            .value = @bitCast(try io.readInt(reader, u32)),
            .grapheme_count = try io.readInt(reader, u32),
        };
    }

    /// Computes the fixed header size using the encoder itself.
    fn computeLen() usize {
        comptime {
            var buf: [128]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&buf);
            CellHeader.encode(.{}, &writer) catch unreachable;
            return writer.end;
        }
    }

    /// Determines how `value` is interpreted.
    pub const Kind = enum(u8) {
        codepoint = 0,
        bg_color_palette = 1,
        bg_color_rgb = 2,
    };

    /// The alternate interpretations of the four-byte content field.
    pub const Value = packed union(u32) {
        codepoint: u32,
        bg_color_palette: packed struct(u32) {
            index: u8,
            _padding: u24 = 0,
        },
        bg_color_rgb: packed struct(u32) {
            r: u8,
            g: u8,
            b: u8,
            _padding: u8 = 0,
        },
    };

    const Flags = packed struct(u8) {
        protected: bool = false,
        semantic_content: SemanticContent = .output,
        _padding: u5 = 0,

        const SemanticContent = enum(u2) {
            output = 0,
            input = 1,
            prompt = 2,
            invalid = 3,
        };
    };
};
