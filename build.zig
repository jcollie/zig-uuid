// SPDX-FileCopyrightText: © 2025 Jeffrey C. Ollie
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("uuid", .{
        .root_source_file = b.path("src/uuid.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "uuidgen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{
                    .name = "uuid",
                    .module = mod,
                },
            },
        }),
        .use_lld = false,
        .use_llvm = false,
    });

    b.installArtifact(exe);

    {
        const run_step = b.step("run", "Run the app");

        const run_cmd = b.addRunArtifact(exe);
        run_step.dependOn(&run_cmd.step);

        run_cmd.step.dependOn(b.getInstallStep());

        if (b.args) |args| {
            run_cmd.addArgs(args);
        }
    }

    {
        const mod_tests = b.addTest(.{
            .root_module = mod,
        });

        const run_mod_tests = b.addRunArtifact(mod_tests);

        const test_step = b.step("test", "Run tests");
        test_step.dependOn(&run_mod_tests.step);
    }

    {
        // The benchmarks always build ReleaseFast, independent of -Doptimize,
        // so they need their own instance of the uuid module built the same
        // way.
        const bench_uuid = b.createModule(.{
            .root_source_file = b.path("src/uuid.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        });

        const bench_exe = b.addExecutable(.{
            .name = "bench",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/bench.zig"),
                .target = target,
                .optimize = .ReleaseFast,
                .imports = &.{
                    .{
                        .name = "uuid",
                        .module = bench_uuid,
                    },
                },
            }),
        });

        const run_bench = b.addRunArtifact(bench_exe);

        const bench_step = b.step("bench", "Run the benchmarks");
        bench_step.dependOn(&run_bench.step);
    }

    {
        const lib = b.addLibrary(.{
            .name = "uuid",
            .root_module = mod,
        });

        const install_docs = b.addInstallDirectory(.{
            .source_dir = lib.getEmittedDocs(),
            .install_dir = .prefix,
            .install_subdir = "docs",
        });

        const docs_step = b.step("docs", "Build the API docs");
        docs_step.dependOn(&install_docs.step);
    }
}
