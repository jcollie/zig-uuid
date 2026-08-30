<!-- SPDX-FileCopyrightText: © 2025 Jeffrey C. Ollie -->
<!-- SPDX-License-Identifier: MIT -->

# RFC 9562 UUIDs for Zig

A Zig library for generating, parsing, and formatting
[RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html) UUIDs.

## Features

- Generate version 1, 2, 3, 4, 5, 6, 7, and 8 UUIDs
- The special `nil` (all zeros) and `max` (all ones) UUIDs
- Parse and format the standard string representation
  (`c232ab00-9414-11ec-b3c8-9f6bdeced846`) and the URN representation
  (`urn:uuid:c232ab00-9414-11ec-b3c8-9f6bdeced846`)
- Implements `format` so UUIDs can be printed directly with `{f}`
- `UUID` is a packed union that is exactly 128 bits — compare UUIDs
  with `a.id == b.id`, or access the version and variant fields via
  `meta`
- No allocations, no dependencies

## Requirements

Zig 0.16.0 or later.

## Installation

Add the dependency to your project:

```sh
zig fetch --save git+https://git.ocjtech.us/jeff/zig-uuid
```

Then in your `build.zig`:

```zig
const uuid = b.dependency("uuid", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("uuid", uuid.module("uuid"));
```

## Examples

Generate a random (version 4) UUID:

```zig
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
```

Generate a timestamp-based, sortable (version 7) UUID:

```zig
const uuid: UUID = .new(.{
    .v7 = .{
        .unix_ts_ms = .{ .timestamp = .now(io, .real) },
        .rng = rng,
    },
});
```

Parse and format:

```zig
const uuid = try UUID.deserialize("c232ab00-9414-11ec-b3c8-9f6bdeced846");
const str: [36]u8 = uuid.serialize();
const urn: [45]u8 = uuid.serializeUrn();
```

Note that for version 3 and 5 UUIDs you compute the MD5 or SHA-1 hash
yourself and pass the digest in via the `hash` field. Version 2 (DCE
Security) UUIDs store only 28 bits of timestamp and 6 bits of clock
sequence, so UUIDs generated within the same ~7 minute window for the
same local ID collide easily — prefer another version unless you
specifically need DCE semantics.

## Standards

- [RFC 9562: Universally Unique IDentifiers (UUIDs)](https://www.rfc-editor.org/rfc/rfc9562.html)
  — the current UUID specification, which this library implements. It
  defines versions 1 and 3 through 8, the `nil` and `max` UUIDs, and
  the string and URN representations, and it obsoletes
  [RFC 4122](https://www.rfc-editor.org/rfc/rfc4122.html).
- [DCE 1.1: Authentication and Security Services](https://pubs.opengroup.org/onlinepubs/9696989899/chap5.htm#tagcjh_08_02_01_01)
  — the Open Group specification that defines version 2 "DCE Security"
  UUIDs. RFC 9562 reserves version 2 but leaves its definition here.

The test suite checks against the example values and test vectors from
RFC 9562, with the name-based v8 example corrected per
[erratum 7929](https://www.rfc-editor.org/errata/eid7929).

## Development

```sh
zig build test   # run the tests
zig build run    # run the example UUID generator
zig build docs   # build the API docs into zig-out/docs
zig build bench  # run the benchmarks (always ReleaseFast)
```

## License

MIT. This project follows the [REUSE](https://reuse.software/)
specification.
