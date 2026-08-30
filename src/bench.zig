// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie
// SPDX-License-Identifier: MIT

//! Benchmarks for the UUID library, run with `zig build bench`.
//!
//! Inputs cycle through a table of 1024 UUIDs and every output byte is
//! folded into an accumulator; both are needed to keep the optimizer from
//! constant-folding or dead-code-eliminating the work being measured.

const std = @import("std");
const UUID = @import("uuid").UUID;

const N = 10_000_000;

fn report(name: []const u8, ns: u64) void {
    const per = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(N));
    const rate = 1e9 / per / 1e6;
    std.debug.print("{s:<16} {d:>8.2} ns/op {d:>8.2} Mop/s\n", .{ name, per, rate });
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var prng = std.Random.DefaultPrng.init(0xdeadbeef);
    const rng = prng.random();

    {
        const t0: std.Io.Timestamp = .now(io, .awake);
        var acc: u128 = 0;
        for (0..N) |_| {
            const id: UUID = .new(.{ .v4 = .{ .rng = rng } });
            acc +%= id.id;
        }
        const ns: u64 = @intCast(t0.durationTo(.now(io, .awake)).nanoseconds);
        std.mem.doNotOptimizeAway(acc);
        report("new v4", ns);
    }

    {
        const t0: std.Io.Timestamp = .now(io, .awake);
        var acc: u128 = 0;
        for (0..N) |i| {
            const id: UUID = .new(.{ .v7 = .{
                .unix_ts_ms = .{ .raw = @truncate(i) },
                .rng = rng,
            } });
            acc +%= id.id;
        }
        const ns: u64 = @intCast(t0.durationTo(.now(io, .awake)).nanoseconds);
        std.mem.doNotOptimizeAway(acc);
        report("new v7", ns);
    }

    var ids: [1024]UUID = undefined;
    for (&ids) |*id| id.* = .new(.{ .v4 = .{ .rng = rng } });
    var strs: [1024][36]u8 = undefined;
    for (&strs, ids) |*s, id| s.* = id.serialize();

    {
        const t0: std.Io.Timestamp = .now(io, .awake);
        var acc: u8 = 0;
        for (0..N) |i| {
            const str = ids[i & 1023].serialize();
            for (str) |c| acc +%= c;
        }
        const ns: u64 = @intCast(t0.durationTo(.now(io, .awake)).nanoseconds);
        std.mem.doNotOptimizeAway(acc);
        report("serialize", ns);
    }

    {
        const t0: std.Io.Timestamp = .now(io, .awake);
        var acc: u8 = 0;
        for (0..N) |i| {
            const str = ids[i & 1023].serializeUrn();
            for (str) |c| acc +%= c;
        }
        const ns: u64 = @intCast(t0.durationTo(.now(io, .awake)).nanoseconds);
        std.mem.doNotOptimizeAway(acc);
        report("serializeUrn", ns);
    }

    {
        const t0: std.Io.Timestamp = .now(io, .awake);
        var acc: u128 = 0;
        for (0..N) |i| {
            const id = try UUID.deserialize(&strs[i & 1023]);
            acc +%= id.id;
        }
        const ns: u64 = @intCast(t0.durationTo(.now(io, .awake)).nanoseconds);
        std.mem.doNotOptimizeAway(acc);
        report("deserialize", ns);
    }

    {
        var buf: [64]u8 = undefined;
        const t0: std.Io.Timestamp = .now(io, .awake);
        var acc: u8 = 0;
        for (0..N) |i| {
            var writer = std.Io.Writer.fixed(&buf);
            try ids[i & 1023].format(&writer);
            for (buf[0..36]) |c| acc +%= c;
        }
        const ns: u64 = @intCast(t0.durationTo(.now(io, .awake)).nanoseconds);
        std.mem.doNotOptimizeAway(acc);
        report("format", ns);
    }
}
