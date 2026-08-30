// SPDX-FileCopyrightText: © 2025 Jeffrey C. Ollie
// SPDX-License-Identifier: MIT

const std = @import("std");
const UUID = @import("uuid").UUID;

pub fn main(init: std.process.Init) void {
    const rng_impl: std.Random.IoSource = .{ .io = init.io };
    const rng = rng_impl.interface();

    const uuid: UUID = .new(.{
        .v4 = .{
            .rng = rng,
        },
    });

    std.debug.print("{f}\n", .{uuid});
}
