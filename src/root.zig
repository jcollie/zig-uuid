//! © 2025 Jeffrey C. Ollie
//!
const std = @import("std");

const assert = std.debug.assert;

/// Parse an unsigned hexadecimal number. Yes, there's a Zig std function for
/// that but it allows `_` in numbers and has extra complexity for allowing
/// signed numbers and numbers of different bases.
fn parse(comptime Result: type, buf: []const u8) UUID.Errors!Result {
    const info = @typeInfo(Result);

    assert(info == .int);
    assert(info.int.signedness == .unsigned);
    assert(info.int.bits == buf.len * 4);

    const Accumulate = std.meta.Int(.unsigned, @max(8, info.int.bits));
    const base: Accumulate = 16;
    var accumulate: Accumulate = 0;

    for (buf) |c| {
        const digit: Accumulate = switch (c) {
            '0'...'9' => c - '0',
            'a'...'z' => c - 'a' + 10,
            'A'...'Z' => c - 'A' + 10,
            else => return error.MalformedUUID,
        };
        accumulate = std.math.mul(Accumulate, accumulate, base) catch return error.MalformedUUID;
        accumulate = std.math.add(Accumulate, accumulate, digit) catch return error.MalformedUUID;
    }

    if (Result == Accumulate) return accumulate;
    return std.math.cast(Result, accumulate) orelse return error.MalformedUUID;
}

/// A RFC9562 UUID
/// https://www.rfc-editor.org/rfc/rfc9562.html
pub const UUID = packed union {
    pub const Errors = error{MalformedUUID};

    pub const Version = enum(u4) {
        v1 = 1,
        v2 = 2,
        v3 = 3,
        v4 = 4,
        v5 = 5,
        v6 = 6,
        v7 = 7,
        v8 = 8,
        _,
    };

    /// Timestamps as used by v1 and v6 UUIDs
    const v1v6Time = packed union {
        /// The number of 100-nanosecond intervals since the beginning of the
        /// UUID epoch, which is 1582-10-15 00:00:00 (the date of the Gregorian
        /// reform to the Christian calendar).
        raw: u60,

        /// Split the timestamp in the order needed for v1 UUIDs
        v1: packed struct(u60) {
            low: u32,
            mid: u16,
            high: u12,
        },

        /// Split the timestamp in the order needed for v6 UUIDs
        v6: packed struct(u60) {
            low: u12,
            mid: u16,
            high: u32,
        },

        test "v1v6Time 1" {
            // https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv1-value
            const t: v1v6Time = .{ .raw = 0x1EC9414C232AB00 };
            try std.testing.expectEqual(0xC232AB00, t.v1.low);
            try std.testing.expectEqual(0x9414, t.v1.mid);
            try std.testing.expectEqual(0x1EC, t.v1.high);
        }

        test "v1v6Time 2" {
            // https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv1-value
            const t: v1v6Time = .{ .raw = 0x1EC9414C232AB00 };
            try std.testing.expectEqual(0x1EC9414C, t.v6.high);
            try std.testing.expectEqual(0x232A, t.v6.mid);
            try std.testing.expectEqual(0xB00, t.v6.low);
        }

        // The number of 100-nanosecond intervals from the UUID epoch
        // (1582-10-15 00:00:00) until the Unix epoch (1970-01-01 00:00:00).
        const uuid_epoch_offset = 0x01b21dd213814000;

        /// Return the current UUID epoch timestamp.
        pub fn now() v1v6Time {
            return .{ .raw = @intCast(@divFloor(std.time.nanoTimestamp(), 100) + uuid_epoch_offset) };
        }

        /// Return the UUID epoch timestamp that corresponds to the given Unix
        /// epoch nanosecond timestamp.
        pub fn fromNanoTimestamp(time: i128) v1v6Time {
            return .{ .raw = @intCast(@divFloor(time, 100) + uuid_epoch_offset) };
        }

        test "fromNanoTimestamp" {
            // https://www.rfc-editor.org/rfc/rfc9562.html#name-test-vectors
            const t = fromNanoTimestamp(0x16D6320C3D4DCC00);
            try std.testing.expectEqual(0x1EC9414C232AB00, t.raw);
        }

        /// Return the Unix epoch nanosecond timestamp that corresponds to our
        /// UUID epoch timestamp.
        pub fn toNanoTimeStamp(self: v1v6Time) i128 {
            return (@as(i128, @intCast(self.raw)) - uuid_epoch_offset) * 100;
        }

        test "toNanoTimestamp" {
            // https://www.rfc-editor.org/rfc/rfc9562.html#name-test-vectors
            const t: v1v6Time = .{ .raw = 0x1EC9414C232AB00 };
            try std.testing.expectEqual(0x16D6320C3D4DCC00, t.toNanoTimeStamp());
        }
    };

    pub const NewOptions = union(Version) {
        v1: struct {
            /// The time in 100-nanosecond intervals since the UUID epoch, which
            /// is 1582-10-15 00:00:00. If this is left null the current time
            /// will be used.
            time: ?v1v6Time = null,
            clock_seq: ?u14 = null,
            node: ?u48 = null,
        },
        v2,
        v3: struct {
            hash: *const [std.crypto.hash.Md5.digest_length]u8,

            pub fn parts(self: @This()) packed struct(u128) {
                low: u62,
                _padding2: u2,
                mid: u12,
                _padding1: u4,
                high: u48,
            } {
                return @bitCast(std.mem.readInt(u128, self.hash, .big));
            }
        },
        v4,
        v5: struct {
            hash: *const [std.crypto.hash.Sha1.digest_length]u8,

            pub fn parts(self: @This()) packed struct(u160) {
                _padding3: u32,
                low: u62,
                _padding2: u2,
                mid: u12,
                _padding1: u4,
                high: u48,
            } {
                return @bitCast(std.mem.readInt(u160, self.hash, .big));
            }
        },
        v6: struct {
            /// The time in 100-nanosecond intervals since the UUID epoch, which
            /// is 1582-10-15 00:00:00. If this is left null the current time
            /// will be used.
            time: ?v1v6Time = null,
            clock_seq: ?u14 = null,
            node: ?u48 = null,
        },
        v7: struct {
            unix_ts_ms: ?u48 = null,
        },
        v8: packed union {
            custom: u122,
            part: packed struct(u122) {
                a: u48,
                b: u12,
                c: u62,
            },
        },
    };

    /// Raw 128 bit UUID, use this for equality comparisons.
    id: u128,

    /// Used to make serializing/deserializing easier
    serializable: packed struct(u128) {
        e: u48,
        d: u16,
        c: u16,
        b: u16,
        a: u32,
    },

    /// Used for checking version/variant.
    meta: packed struct(u128) {
        _padding3: u62,
        variant: u2,
        _padding2: u12,
        version: Version,
        _padding1: u48,
    },

    /// Version 1 UUID
    /// https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-1
    v1: packed struct(u128) {
        node: u48,
        clock_seq: u14,
        variant: u2 = 0b10,
        time_high: u12,
        version: Version = .v1,
        time_mid: u16,
        time_low: u32,
    },

    /// Version 2 UUID
    /// https://pubs.opengroup.org/onlinepubs/9696989899/chap5.htm#tagcjh_08_02_01_01
    v2: packed struct(u128) {
        node: u48,
        local_domain: u8,
        clock_seq_hi: u6,
        variant: u2 = 0b10,
        time_high: u12,
        version: Version = .v2,
        time_mid: u16,
        local_id: u32,
    },

    /// Version 3 UUID
    /// https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-3
    v3: packed struct(u128) {
        md5_low: u62,
        variant: u2 = 0b10,
        md5_mid: u12,
        version: Version = .v3,
        md5_high: u48,
    },

    /// Version 4 UUID
    /// https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-4
    v4: packed struct(u128) {
        random_c: u62,
        variant: u2 = 0b10,
        random_b: u12,
        version: Version = .v4,
        random_a: u48,
    },

    /// Version 5 UUID
    /// https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-5
    v5: packed struct(u128) {
        sha1_low: u62,
        variant: u2 = 0b10,
        sha1_mid: u12,
        version: Version = .v5,
        sha1_high: u48,
    },

    /// Version 6 UUID
    /// https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-6
    v6: packed struct(u128) {
        node: u48,
        clock_seq: u14,
        variant: u2 = 0b10,
        time_low: u12,
        version: Version = .v6,
        time_mid: u16,
        time_high: u32,
    },

    /// Version 7 UUID
    /// https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-7
    v7: packed struct(u128) {
        rand_b: u62,
        variant: u2 = 0b10,
        rand_a: u12,
        version: Version = .v7,
        unix_ts_ms: u48,
    },

    /// Version 8 UUID
    /// https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-8
    v8: packed struct(u128) {
        custom_c: u62,
        variant: u2 = 0b10,
        custom_b: u12,
        version: Version = .v8,
        custom_a: u48,
    },

    /// https://www.rfc-editor.org/rfc/rfc9562.html#name-nil-uuid
    pub const nil: UUID = .{ .id = 0 };

    /// https://www.rfc-editor.org/rfc/rfc9562.html#name-max-uuid
    pub const max: UUID = .{ .id = std.math.maxInt(u128) };

    pub fn new(options: NewOptions) UUID {
        switch (options) {
            .v1 => |v| {
                const time = v.time orelse v1v6Time.now();
                const clock_seq = v.clock_seq orelse std.crypto.random.int(u14);
                const node = v.node orelse (std.crypto.random.int(u48) | 0x1000_0000_0000);

                return .{
                    .v1 = .{
                        .time_low = time.v1.low,
                        .time_mid = time.v1.mid,
                        .time_high = time.v1.high,
                        .clock_seq = clock_seq,
                        .node = node,
                    },
                };
            },

            .v2 => unreachable,

            .v3 => |v| {
                const parts = v.parts();
                return .{
                    .v3 = .{
                        .md5_high = parts.high,
                        .md5_mid = parts.mid,
                        .md5_low = parts.low,
                    },
                };
            },

            .v4 => {
                var id: UUID = .{ .id = std.crypto.random.int(u128) };
                id.v4.version = .v4;
                id.v4.variant = 0b10;
                return id;
            },

            .v5 => |v| {
                const parts = v.parts();
                return .{
                    .v5 = .{
                        .sha1_high = parts.high,
                        .sha1_mid = parts.mid,
                        .sha1_low = parts.low,
                    },
                };
            },

            .v6 => |v| {
                const time = v.time orelse v1v6Time.now();
                const clock_seq = v.clock_seq orelse std.crypto.random.int(u14);
                // if we didn't get a node, create a random one and set the multicast bit
                const node = v.node orelse (std.crypto.random.int(u48) | 0x100000000000);

                return .{
                    .v6 = .{
                        .time_low = time.v6.low,
                        .time_mid = time.v6.mid,
                        .time_high = time.v6.high,
                        .clock_seq = clock_seq,
                        .node = node,
                    },
                };
            },

            .v7 => |v| {
                var id: UUID = .{ .id = std.crypto.random.int(u128) };
                id.v7.unix_ts_ms = v.unix_ts_ms orelse @intCast(std.time.milliTimestamp());
                id.v7.version = .v7;
                id.v7.variant = 0b10;
                return id;
            },

            .v8 => |v| {
                return .{
                    .v8 = .{
                        .custom_a = v.part.a,
                        .custom_b = v.part.b,
                        .custom_c = v.part.c,
                    },
                };
            },
        }
    }

    pub fn serialize(self: UUID) [36]u8 {
        var buf: [36]u8 = undefined;
        _ = std.fmt.bufPrint(
            &buf,
            "{x:0>8}-{x:0>4}-{x:0>4}-{x:0>4}-{x:0>12}",
            .{
                self.serializable.a,
                self.serializable.b,
                self.serializable.c,
                self.serializable.d,
                self.serializable.e,
            },
        ) catch unreachable;
        return buf;
    }

    pub fn serializeZ(self: UUID) [36:0]u8 {
        var buf: [36:0]u8 = undefined;
        _ = std.fmt.bufPrint(
            &buf,
            "{x:0>8}-{x:0>4}-{x:0>4}-{x:0>4}-{x:0>12}",
            .{
                self.serializable.a,
                self.serializable.b,
                self.serializable.c,
                self.serializable.d,
                self.serializable.e,
            },
        ) catch unreachable;
        buf[buf.len] = 0;
        return buf;
    }

    pub fn deserialize(str: []const u8) Errors!UUID {
        if (str.len != 36) return error.MalformedUUID;
        inline for (.{ 8, 13, 18, 23 }) |i| if (str[i] != '-') return error.MalformedUUID;
        return .{
            .serializable = .{
                .a = try parse(u32, str[0..8]),
                .b = try parse(u16, str[9..13]),
                .c = try parse(u16, str[14..18]),
                .d = try parse(u16, str[19..23]),
                .e = try parse(u48, str[24..36]),
            },
        };
    }

    pub fn serializeUrn(self: UUID) [45]u8 {
        var buf: [45]u8 = undefined;
        @memcpy(buf[0..9], "urn:uuid:");
        _ = std.fmt.bufPrint(
            buf[9..],
            "{x:0>8}-{x:0>4}-{x:0>4}-{x:0>4}-{x:0>12}",
            .{
                self.serializable.a,
                self.serializable.b,
                self.serializable.c,
                self.serializable.d,
                self.serializable.e,
            },
        ) catch unreachable;
        return buf;
    }

    pub fn serializeUrnZ(self: UUID) [45:0]u8 {
        var buf: [45]u8 = undefined;
        @memcpy(buf[0..9], "urn:uuid:");
        _ = std.fmt.bufPrint(
            buf[9..],
            "{x:0>8}-{x:0>4}-{x:0>4}-{x:0>4}-{x:0>12}",
            .{
                self.serializable.a,
                self.serializable.b,
                self.serializable.c,
                self.serializable.d,
                self.serializable.e,
            },
        ) catch unreachable;
        buf[buf.len] = 0;
        return buf;
    }

    pub fn deserializeUrn(urn: []const u8) Errors!UUID {
        if (urn.len != 45) return error.MalformedUUID;
        if (!std.mem.eql(u8, "urn:uuid:", urn[0..9])) return error.MalformedUUID;
        return try deserialize(urn[9..]);
    }
};

test "uuid test 1" {
    const id1: UUID = .new(.v4);
    const str = id1.serialize();
    const id2 = try UUID.deserialize(&str);
    try std.testing.expectEqual(id2.id, id1.id);
}

test "uuid test 2" {
    const id1: UUID = .new(.{ .v7 = .{} });
    const str = id1.serialize();
    const id2 = try UUID.deserialize(&str);
    try std.testing.expectEqual(id2.id, id1.id);
}

test "uuid test 3" {
    {
        // https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv1-value
        const id: UUID = .{
            .v1 = .{
                .time_low = 0xC232AB00,
                .time_mid = 0x9414,
                .time_high = 0x1EC,
                .clock_seq = 0x33C8,
                .node = 0x9F6BDECED846,
            },
        };

        {
            const str = id.serialize();
            try std.testing.expectEqualStrings("c232ab00-9414-11ec-b3c8-9f6bdeced846", &str);
        }
        {
            const str = id.serializeZ();
            try std.testing.expectEqualSentinel(u8, 0, "c232ab00-9414-11ec-b3c8-9f6bdeced846", &str);
        }
    }

    {
        // https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv1-value
        const id: UUID = .new(
            .{
                .v1 = .{
                    .time = .{
                        .raw = 0x1EC9414C232AB00,
                    },
                    .clock_seq = 0x33C8,
                    .node = 0x9F6BDECED846,
                },
            },
        );

        try std.testing.expectEqual(.v1, id.meta.version);
        try std.testing.expectEqual(0b10, id.meta.variant);

        {
            const str = id.serialize();
            try std.testing.expectEqualStrings("c232ab00-9414-11ec-b3c8-9f6bdeced846", &str);
        }
        {
            const str = id.serializeZ();
            try std.testing.expectEqualSentinel(u8, 0, "c232ab00-9414-11ec-b3c8-9f6bdeced846", &str);
        }
    }

    {
        // https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv3-value

        const id: UUID = .{
            .v3 = .{
                .md5_high = 0x5df418813aed,
                .md5_mid = 0x515,
                .md5_low = 0x08a72f4a814cf09e,
            },
        };

        try std.testing.expectEqual(.v3, id.meta.version);
        try std.testing.expectEqual(0b10, id.meta.variant);

        {
            const str = id.serialize();
            try std.testing.expectEqualStrings("5df41881-3aed-3515-88a7-2f4a814cf09e", &str);
        }
        {
            const str = id.serializeZ();
            try std.testing.expectEqualSentinel(u8, 0, "5df41881-3aed-3515-88a7-2f4a814cf09e", &str);
        }
    }

    {
        // https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv3-value

        const id: UUID = .new(.{
            .v3 = .{
                .hash = &[_]u8{ 0x5d, 0xf4, 0x18, 0x81, 0x3a, 0xed, 0x05, 0x15, 0x48, 0xa7, 0x2f, 0x4a, 0x81, 0x4c, 0xf0, 0x9e },
            },
        });

        try std.testing.expectEqual(.v3, id.meta.version);
        try std.testing.expectEqual(0b10, id.meta.variant);

        {
            const str = id.serialize();
            try std.testing.expectEqualStrings("5df41881-3aed-3515-88a7-2f4a814cf09e", &str);
        }
        {
            const str = id.serializeZ();
            try std.testing.expectEqualSentinel(u8, 0, "5df41881-3aed-3515-88a7-2f4a814cf09e", &str);
        }
    }

    {
        // https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv4-value
        const id: UUID = .{
            .v4 = .{
                .random_a = 0x919108f752d1,
                .random_b = 0x320,
                .random_c = 0x01bacf847db4148a8,
            },
        };

        try std.testing.expectEqual(.v4, id.meta.version);
        try std.testing.expectEqual(0b10, id.meta.variant);

        {
            const str = id.serialize();
            try std.testing.expectEqualStrings("919108f7-52d1-4320-9bac-f847db4148a8", &str);
        }
        {
            const str = id.serializeZ();
            try std.testing.expectEqualSentinel(u8, 0, "919108f7-52d1-4320-9bac-f847db4148a8", &str);
        }
    }

    {
        // https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-5
        const id: UUID = .{
            .v5 = .{
                .sha1_high = 0x2ed6657de927,
                .sha1_mid = 0x68b,
                .sha1_low = 0x15e12665a8aea6a2,
            },
        };

        try std.testing.expectEqual(.v5, id.meta.version);
        try std.testing.expectEqual(0b10, id.meta.variant);

        {
            const str = id.serialize();
            try std.testing.expectEqualStrings("2ed6657d-e927-568b-95e1-2665a8aea6a2", &str);
        }
        {
            const str = id.serializeZ();
            try std.testing.expectEqualSentinel(u8, 0, "2ed6657d-e927-568b-95e1-2665a8aea6a2", &str);
        }
    }

    {
        // https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-5
        const id: UUID = .new(
            .{
                .v5 = .{
                    .hash = &[_]u8{ 0x2e, 0xd6, 0x65, 0x7d, 0xe9, 0x27, 0x46, 0x8b, 0x55, 0xe1, 0x26, 0x65, 0xa8, 0xae, 0xa6, 0xa2, 0x2d, 0xee, 0x3e, 0x35 },
                },
            },
        );

        try std.testing.expectEqual(.v5, id.meta.version);
        try std.testing.expectEqual(0b10, id.meta.variant);

        {
            const str = id.serialize();
            try std.testing.expectEqualStrings("2ed6657d-e927-568b-95e1-2665a8aea6a2", &str);
        }
        {
            const str = id.serializeZ();
            try std.testing.expectEqualSentinel(u8, 0, "2ed6657d-e927-568b-95e1-2665a8aea6a2", &str);
        }
    }

    {
        // https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv6-value
        const id: UUID = .{
            .v6 = .{
                .time_high = 0x1EC9414C,
                .time_mid = 0x232A,
                .time_low = 0xB00,
                .clock_seq = 0x33C8,
                .node = 0x9F6BDECED846,
            },
        };

        try std.testing.expectEqual(.v6, id.meta.version);
        try std.testing.expectEqual(0b10, id.meta.variant);

        {
            const str = id.serialize();
            try std.testing.expectEqualStrings("1ec9414c-232a-6b00-b3c8-9f6bdeced846", &str);
        }
        {
            const str = id.serializeZ();
            try std.testing.expectEqualSentinel(u8, 0, "1ec9414c-232a-6b00-b3c8-9f6bdeced846", &str);
        }
    }

    {
        // https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv7-value
        const id: UUID = .{
            .v7 = .{
                .unix_ts_ms = 0x017F22E279B0,
                .rand_a = 0xCC3,
                .rand_b = 0x18C4DC0C0C07398F,
            },
        };

        try std.testing.expectEqual(.v7, id.meta.version);
        try std.testing.expectEqual(0b10, id.meta.variant);

        {
            const str = id.serialize();
            try std.testing.expectEqualStrings("017f22e2-79b0-7cc3-98c4-dc0c0c07398f", &str);
        }
        {
            const str = id.serializeZ();
            try std.testing.expectEqualSentinel(u8, 0, "017f22e2-79b0-7cc3-98c4-dc0c0c07398f", &str);
        }
    }

    {
        // https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv8-value-t
        const id: UUID = .{
            .v8 = .{
                .custom_a = 0x2489E9AD2EE2,
                .custom_b = 0xE00,
                .custom_c = 0x0EC932D5F69181C0,
            },
        };

        try std.testing.expectEqual(.v8, id.meta.version);
        try std.testing.expectEqual(0b10, id.meta.variant);

        {
            const str = id.serialize();
            try std.testing.expectEqualStrings("2489e9ad-2ee2-8e00-8ec9-32d5f69181c0", &str);
        }
        {
            const str = id.serializeZ();
            try std.testing.expectEqualSentinel(u8, 0, "2489e9ad-2ee2-8e00-8ec9-32d5f69181c0", &str);
        }
    }

    {
        // https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv8-value-n
        // https://www.rfc-editor.org/errata/eid7929
        const id: UUID = .{
            .v8 = .{
                .custom_a = 0x5c146b143c52,
                .custom_b = 0xafd,
                .custom_c = 0x138a375d0df1fbf6,
            },
        };

        try std.testing.expectEqual(.v8, id.meta.version);
        try std.testing.expectEqual(0b10, id.meta.variant);

        {
            const str = id.serialize();
            try std.testing.expectEqualStrings("5c146b14-3c52-8afd-938a-375d0df1fbf6", &str);
        }
        {
            const str = id.serializeZ();
            try std.testing.expectEqualSentinel(u8, 0, "5c146b14-3c52-8afd-938a-375d0df1fbf6", &str);
        }
    }
}

test "uuid test 4" {
    // 100 test cases generated with Python:
    //
    // import uuid
    // for i in range(0,100):
    //     u = uuid.uuid4()
    //     print(f".{{ .id = .{{ .id = 0x{u.hex} }}, .str = \"{str(u)}\" }},")
    //
    const cases = [_]struct { id: UUID, str: []const u8 }{
        .{ .id = .{ .id = 0xee16e1f2806f4a81b5efe56eb34caa4e }, .str = "ee16e1f2-806f-4a81-b5ef-e56eb34caa4e" },
        .{ .id = .{ .id = 0x9504a885e4fc4e87a80e0ae0c29cf7db }, .str = "9504a885-e4fc-4e87-a80e-0ae0c29cf7db" },
        .{ .id = .{ .id = 0xeed5c8b49a9842fda0b3082600526961 }, .str = "eed5c8b4-9a98-42fd-a0b3-082600526961" },
        .{ .id = .{ .id = 0x321168df2bc74e2c952d1218dfac2447 }, .str = "321168df-2bc7-4e2c-952d-1218dfac2447" },
        .{ .id = .{ .id = 0x87b06df3b05c4291a7dc87d2e4196e81 }, .str = "87b06df3-b05c-4291-a7dc-87d2e4196e81" },
        .{ .id = .{ .id = 0x977951474c1143679acb8e55fa0b85a8 }, .str = "97795147-4c11-4367-9acb-8e55fa0b85a8" },
        .{ .id = .{ .id = 0x0228a76e5e7e439da43b0d5584e8cbd1 }, .str = "0228a76e-5e7e-439d-a43b-0d5584e8cbd1" },
        .{ .id = .{ .id = 0x868f3440ba474e7fae0b5992f29e2fb5 }, .str = "868f3440-ba47-4e7f-ae0b-5992f29e2fb5" },
        .{ .id = .{ .id = 0xc215d4e8ad7c49dcb3a1446107c55f5c }, .str = "c215d4e8-ad7c-49dc-b3a1-446107c55f5c" },
        .{ .id = .{ .id = 0xcb5f9d06166449938806841473248054 }, .str = "cb5f9d06-1664-4993-8806-841473248054" },
        .{ .id = .{ .id = 0x40c638e0c78e448faa63b2981fcf0a16 }, .str = "40c638e0-c78e-448f-aa63-b2981fcf0a16" },
        .{ .id = .{ .id = 0x88d5fa6b73b84ba495aa38fb7a0c834d }, .str = "88d5fa6b-73b8-4ba4-95aa-38fb7a0c834d" },
        .{ .id = .{ .id = 0x8eee0e35c6c8474da7f1fceeb3de3d31 }, .str = "8eee0e35-c6c8-474d-a7f1-fceeb3de3d31" },
        .{ .id = .{ .id = 0x8bd989819195406682fd82643d0dbea9 }, .str = "8bd98981-9195-4066-82fd-82643d0dbea9" },
        .{ .id = .{ .id = 0xfbbe61f6f4b2493183ce122577684e2a }, .str = "fbbe61f6-f4b2-4931-83ce-122577684e2a" },
        .{ .id = .{ .id = 0xdb967b0d70f3448da57fac344a159b89 }, .str = "db967b0d-70f3-448d-a57f-ac344a159b89" },
        .{ .id = .{ .id = 0x992b414bd2f14833ba0d1f3550919709 }, .str = "992b414b-d2f1-4833-ba0d-1f3550919709" },
        .{ .id = .{ .id = 0x75c5421f329941129a7fe33c6a04a54d }, .str = "75c5421f-3299-4112-9a7f-e33c6a04a54d" },
        .{ .id = .{ .id = 0xe1f1175cc25d4b2badcb6df26bbfad8e }, .str = "e1f1175c-c25d-4b2b-adcb-6df26bbfad8e" },
        .{ .id = .{ .id = 0xd11993823db0424498b7d6c73df9b9a9 }, .str = "d1199382-3db0-4244-98b7-d6c73df9b9a9" },
        .{ .id = .{ .id = 0x12f7fc12c8834690bf3c9b513b80cc53 }, .str = "12f7fc12-c883-4690-bf3c-9b513b80cc53" },
        .{ .id = .{ .id = 0x31244efe2b2e42c5a9db4c3db8d5d8f4 }, .str = "31244efe-2b2e-42c5-a9db-4c3db8d5d8f4" },
        .{ .id = .{ .id = 0xb10d719705af49a1b55ce7f0845a1e40 }, .str = "b10d7197-05af-49a1-b55c-e7f0845a1e40" },
        .{ .id = .{ .id = 0x6c12f609684641108036caae1bcf232b }, .str = "6c12f609-6846-4110-8036-caae1bcf232b" },
        .{ .id = .{ .id = 0x39621458cba14aa8b7fea4a9fa842404 }, .str = "39621458-cba1-4aa8-b7fe-a4a9fa842404" },
        .{ .id = .{ .id = 0x2624801c09104d968f21420eaf5c36c2 }, .str = "2624801c-0910-4d96-8f21-420eaf5c36c2" },
        .{ .id = .{ .id = 0x2a554d1668c54948a58b796ca3cbfff4 }, .str = "2a554d16-68c5-4948-a58b-796ca3cbfff4" },
        .{ .id = .{ .id = 0x1f25dd9f8195447e8247808f9f79f0de }, .str = "1f25dd9f-8195-447e-8247-808f9f79f0de" },
        .{ .id = .{ .id = 0xa796090cb9da49409f9533dd703d9530 }, .str = "a796090c-b9da-4940-9f95-33dd703d9530" },
        .{ .id = .{ .id = 0x5d7b46b59aee4939a8fd9cc7495c3589 }, .str = "5d7b46b5-9aee-4939-a8fd-9cc7495c3589" },
        .{ .id = .{ .id = 0x173879d8fdb544439e91bcd3dd9c8dae }, .str = "173879d8-fdb5-4443-9e91-bcd3dd9c8dae" },
        .{ .id = .{ .id = 0x90a32113f57d47ee9ee59752efe7e922 }, .str = "90a32113-f57d-47ee-9ee5-9752efe7e922" },
        .{ .id = .{ .id = 0x4ddf8bbaa536476bb7fa015033dbd646 }, .str = "4ddf8bba-a536-476b-b7fa-015033dbd646" },
        .{ .id = .{ .id = 0x7d7762d39d6d49539a2dc815834e0179 }, .str = "7d7762d3-9d6d-4953-9a2d-c815834e0179" },
        .{ .id = .{ .id = 0x32c5ac110d1046ea885d76cabed8feee }, .str = "32c5ac11-0d10-46ea-885d-76cabed8feee" },
        .{ .id = .{ .id = 0x0c3a38c9157643fab7459fd9c60654ab }, .str = "0c3a38c9-1576-43fa-b745-9fd9c60654ab" },
        .{ .id = .{ .id = 0x8a7709e07c0e4329af5fefd6f5a5707d }, .str = "8a7709e0-7c0e-4329-af5f-efd6f5a5707d" },
        .{ .id = .{ .id = 0x02b728c6ef834c7c961048ca94c7dc8c }, .str = "02b728c6-ef83-4c7c-9610-48ca94c7dc8c" },
        .{ .id = .{ .id = 0xff2c6d0b05d8444aae94f484bbaf3f67 }, .str = "ff2c6d0b-05d8-444a-ae94-f484bbaf3f67" },
        .{ .id = .{ .id = 0x28d403e8ff7f41dfa08e0c949c36429c }, .str = "28d403e8-ff7f-41df-a08e-0c949c36429c" },
        .{ .id = .{ .id = 0x5f4a93cb967347cc93fc93ab2b1ef2d3 }, .str = "5f4a93cb-9673-47cc-93fc-93ab2b1ef2d3" },
        .{ .id = .{ .id = 0xfafde273adf441bc82cb739bc9b74911 }, .str = "fafde273-adf4-41bc-82cb-739bc9b74911" },
        .{ .id = .{ .id = 0x9221cda90255405685585d9508cf1713 }, .str = "9221cda9-0255-4056-8558-5d9508cf1713" },
        .{ .id = .{ .id = 0x7b17d649726e444785d2a35917b8cd27 }, .str = "7b17d649-726e-4447-85d2-a35917b8cd27" },
        .{ .id = .{ .id = 0x4f8c45c12c3e4b8b93171c6f7096c10b }, .str = "4f8c45c1-2c3e-4b8b-9317-1c6f7096c10b" },
        .{ .id = .{ .id = 0x7e1ed5e82d274935a42a248820544539 }, .str = "7e1ed5e8-2d27-4935-a42a-248820544539" },
        .{ .id = .{ .id = 0xbd53a0ca37c741168bd6ac0be15bbe62 }, .str = "bd53a0ca-37c7-4116-8bd6-ac0be15bbe62" },
        .{ .id = .{ .id = 0x41612ef7202c4e239f4f7d427a61d9f4 }, .str = "41612ef7-202c-4e23-9f4f-7d427a61d9f4" },
        .{ .id = .{ .id = 0x6fbc2449cf8c4992b3236650b5c43c41 }, .str = "6fbc2449-cf8c-4992-b323-6650b5c43c41" },
        .{ .id = .{ .id = 0x485d909f5fcd4f77a9ab58914e6507b0 }, .str = "485d909f-5fcd-4f77-a9ab-58914e6507b0" },
        .{ .id = .{ .id = 0x495efafd48694ffb98d91c804e3ce229 }, .str = "495efafd-4869-4ffb-98d9-1c804e3ce229" },
        .{ .id = .{ .id = 0x8259b4f9405e492d80a6aca2539a6d0c }, .str = "8259b4f9-405e-492d-80a6-aca2539a6d0c" },
        .{ .id = .{ .id = 0xbed2dafbb90440159ccef782191e6b3f }, .str = "bed2dafb-b904-4015-9cce-f782191e6b3f" },
        .{ .id = .{ .id = 0xfa2aa9101e2c45599bc36db48a475676 }, .str = "fa2aa910-1e2c-4559-9bc3-6db48a475676" },
        .{ .id = .{ .id = 0xe8d31f6009754043b27eaceca9ea08c6 }, .str = "e8d31f60-0975-4043-b27e-aceca9ea08c6" },
        .{ .id = .{ .id = 0xf631d923d1a24f9c905caff5f2e623ed }, .str = "f631d923-d1a2-4f9c-905c-aff5f2e623ed" },
        .{ .id = .{ .id = 0xe8e7d8852c6a48d8a4bd336c7e61bb5d }, .str = "e8e7d885-2c6a-48d8-a4bd-336c7e61bb5d" },
        .{ .id = .{ .id = 0x196c0427adda40a4bb6eb2fe1cb70570 }, .str = "196c0427-adda-40a4-bb6e-b2fe1cb70570" },
        .{ .id = .{ .id = 0x22cc7984ced74084bb2678b1a3ff1c76 }, .str = "22cc7984-ced7-4084-bb26-78b1a3ff1c76" },
        .{ .id = .{ .id = 0x09a3a01c0c1e4224bd967a0885e24be9 }, .str = "09a3a01c-0c1e-4224-bd96-7a0885e24be9" },
        .{ .id = .{ .id = 0x304fe7732e474a7993653728aeb76ba5 }, .str = "304fe773-2e47-4a79-9365-3728aeb76ba5" },
        .{ .id = .{ .id = 0x54cca6a4d6974d67849c1c97c5e75af3 }, .str = "54cca6a4-d697-4d67-849c-1c97c5e75af3" },
        .{ .id = .{ .id = 0xf209401eb8834ff9b1d50abe729d6cbd }, .str = "f209401e-b883-4ff9-b1d5-0abe729d6cbd" },
        .{ .id = .{ .id = 0xfa48e76d1a3544a195a8ff7c3260e701 }, .str = "fa48e76d-1a35-44a1-95a8-ff7c3260e701" },
        .{ .id = .{ .id = 0xc608661a96964d6db5da261768fffafb }, .str = "c608661a-9696-4d6d-b5da-261768fffafb" },
        .{ .id = .{ .id = 0x525bc80a22b04df596ce8faab862e8c3 }, .str = "525bc80a-22b0-4df5-96ce-8faab862e8c3" },
        .{ .id = .{ .id = 0x3de673b3663240f9bbb6fae9a7c1b5c9 }, .str = "3de673b3-6632-40f9-bbb6-fae9a7c1b5c9" },
        .{ .id = .{ .id = 0x706fb5f549ca48c58770bd67d06b23f8 }, .str = "706fb5f5-49ca-48c5-8770-bd67d06b23f8" },
        .{ .id = .{ .id = 0x79b7ceaf4d5b4ff9ac868fe7e3f1ea86 }, .str = "79b7ceaf-4d5b-4ff9-ac86-8fe7e3f1ea86" },
        .{ .id = .{ .id = 0x610f0323fe0449fd8c1dfa01228af435 }, .str = "610f0323-fe04-49fd-8c1d-fa01228af435" },
        .{ .id = .{ .id = 0x5c3e368a22ee4014a8eb69b117e75dbe }, .str = "5c3e368a-22ee-4014-a8eb-69b117e75dbe" },
        .{ .id = .{ .id = 0x19128edbe3534c31994785b59efc45ac }, .str = "19128edb-e353-4c31-9947-85b59efc45ac" },
        .{ .id = .{ .id = 0x9143e6a064ae4a02a31dabd0fcb08ead }, .str = "9143e6a0-64ae-4a02-a31d-abd0fcb08ead" },
        .{ .id = .{ .id = 0xa6b8ee09ada5425491420c894e36d8e1 }, .str = "a6b8ee09-ada5-4254-9142-0c894e36d8e1" },
        .{ .id = .{ .id = 0x8dbac146b53f40c3974041366da44d16 }, .str = "8dbac146-b53f-40c3-9740-41366da44d16" },
        .{ .id = .{ .id = 0x28d6f669b30b43328be0d0e46a67fb02 }, .str = "28d6f669-b30b-4332-8be0-d0e46a67fb02" },
        .{ .id = .{ .id = 0xe109fcc3b7b042acbc9f0ba7a6442bcc }, .str = "e109fcc3-b7b0-42ac-bc9f-0ba7a6442bcc" },
        .{ .id = .{ .id = 0x42abab84aa11459ba8017b0dd227bb52 }, .str = "42abab84-aa11-459b-a801-7b0dd227bb52" },
        .{ .id = .{ .id = 0x92504baad1d8453796f56edfecf773f2 }, .str = "92504baa-d1d8-4537-96f5-6edfecf773f2" },
        .{ .id = .{ .id = 0x500fc4e1519f4239968f44632eb06c00 }, .str = "500fc4e1-519f-4239-968f-44632eb06c00" },
        .{ .id = .{ .id = 0xa4f76ace36ff45138b684a471b745403 }, .str = "a4f76ace-36ff-4513-8b68-4a471b745403" },
        .{ .id = .{ .id = 0x79e3072d3fcc435cbb8cb47cdcd14244 }, .str = "79e3072d-3fcc-435c-bb8c-b47cdcd14244" },
        .{ .id = .{ .id = 0xffa944e135cd4f48bb105fea5ada725e }, .str = "ffa944e1-35cd-4f48-bb10-5fea5ada725e" },
        .{ .id = .{ .id = 0x77a89304b0b04bb1b3aac5944990c627 }, .str = "77a89304-b0b0-4bb1-b3aa-c5944990c627" },
        .{ .id = .{ .id = 0xdf6e0bdb38694e9faf67332619fd3e5c }, .str = "df6e0bdb-3869-4e9f-af67-332619fd3e5c" },
        .{ .id = .{ .id = 0x3fd6d33349814062b448d996864b613d }, .str = "3fd6d333-4981-4062-b448-d996864b613d" },
        .{ .id = .{ .id = 0xd6e53cb31474477391e8e468fe538406 }, .str = "d6e53cb3-1474-4773-91e8-e468fe538406" },
        .{ .id = .{ .id = 0xedd499e607da42bdbd1a5ba7771b2294 }, .str = "edd499e6-07da-42bd-bd1a-5ba7771b2294" },
        .{ .id = .{ .id = 0xea22daec2f0f4e0ebd497c994726871c }, .str = "ea22daec-2f0f-4e0e-bd49-7c994726871c" },
        .{ .id = .{ .id = 0xc833125f0ffe4e728c7dbe69ccfedb3a }, .str = "c833125f-0ffe-4e72-8c7d-be69ccfedb3a" },
        .{ .id = .{ .id = 0x24a66fb235f843cab808cbe5a77153ff }, .str = "24a66fb2-35f8-43ca-b808-cbe5a77153ff" },
        .{ .id = .{ .id = 0xbce52670a2014b278ed1a7a3f9d0d971 }, .str = "bce52670-a201-4b27-8ed1-a7a3f9d0d971" },
        .{ .id = .{ .id = 0x881dcff4a3d042159e35a93f130c9d25 }, .str = "881dcff4-a3d0-4215-9e35-a93f130c9d25" },
        .{ .id = .{ .id = 0x6cf5af0efda44620a0656e182318788d }, .str = "6cf5af0e-fda4-4620-a065-6e182318788d" },
        .{ .id = .{ .id = 0x7b4393b71ee648f4b2287f8ee1ecc65d }, .str = "7b4393b7-1ee6-48f4-b228-7f8ee1ecc65d" },
        .{ .id = .{ .id = 0xc2af2cd67c7346bba893ad256c566bf5 }, .str = "c2af2cd6-7c73-46bb-a893-ad256c566bf5" },
        .{ .id = .{ .id = 0xe799dfb4dd364c969659f0f467da41db }, .str = "e799dfb4-dd36-4c96-9659-f0f467da41db" },
        .{ .id = .{ .id = 0x78b04189694942be98e2fa336e98b81b }, .str = "78b04189-6949-42be-98e2-fa336e98b81b" },
        .{ .id = .{ .id = 0x182b88d03b754e52b3f19004c00d57e0 }, .str = "182b88d0-3b75-4e52-b3f1-9004c00d57e0" },
        .{ .id = .{ .id = 0x7235ba7b929e4dcb9ea1cd06a5d225da }, .str = "7235ba7b-929e-4dcb-9ea1-cd06a5d225da" },
    };

    for (cases) |case| {
        const id1 = try UUID.deserialize(case.str);
        try std.testing.expectEqual(case.id.id, id1.id);
        try std.testing.expectEqual(.v4, id1.meta.version);
        try std.testing.expectEqual(2, id1.meta.variant);

        const str1 = case.id.serialize();
        try std.testing.expectEqualStrings(case.str, &str1);

        const id2 = try UUID.deserialize(&str1);
        try std.testing.expectEqual(case.id.id, id2.id);
        try std.testing.expectEqual(.v4, id2.meta.version);
        try std.testing.expectEqual(2, id2.meta.variant);

        try std.testing.expectEqual(id1.id, id2.id);

        const urn1 = id1.serializeUrn();
        const id3 = try UUID.deserializeUrn(&urn1);
        try std.testing.expectEqual(case.id.id, id3.id);
        try std.testing.expectEqual(id1.id, id3.id);
    }
}
