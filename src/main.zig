const std = @import("std");

var global_io: std.Io = undefined;

const forbidden = [_][]const u8{
    "dev-secret-change-me",
    "secret-key-change-me",
    "changeme-secret",
};

fn out(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(text);
    try std.Io.File.stdout().writeStreamingAll(global_io, text);
}

fn containsAny(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (std.mem.indexOf(u8, haystack, needle) != null) return true;
    }
    return false;
}

fn scanFile(allocator: std.mem.Allocator, path: []const u8) !usize {
    const data = std.Io.Dir.cwd().readFileAlloc(global_io, path, allocator, std.Io.Limit.limited(8 * 1024 * 1024)) catch return 0;
    defer allocator.free(data);

    const has_warning = containsAny(data, &.{ "warn", "aviso", "advert" });
    const is_requirements = std.mem.startsWith(u8, std.fs.path.basename(path), "requirements");
    var findings: usize = 0;

    var lines = std.mem.splitScalar(u8, data, '\n');
    var lineno: usize = 0;
    while (lines.next()) |raw| {
        lineno += 1;
        const line = std.mem.trim(u8, raw, " \t\r");

        for (forbidden) |token| {
            if (std.mem.indexOf(u8, line, token) != null) {
                try out(allocator, "[critical] HARD-01 {s}:{d} {s}\n", .{ path, lineno, token });
                findings += 1;
            }
        }
        if (std.mem.indexOf(u8, line, "0.0.0.0") != null and
            containsAny(line, &.{ "defaultAddr", "bind", "listen" }))
        {
            try out(allocator, "[high] HARD-03 {s}:{d} bind 0.0.0.0\n", .{ path, lineno });
            findings += 1;
        }
        if (containsAny(line, &.{ "C2_ALLOW_", "verify=False", "verify = False", "InsecureSkipVerify" })) {
            if (std.mem.indexOf(u8, line, "verify") != null or std.mem.indexOf(u8, line, "InsecureSkipVerify") != null) {
                try out(allocator, "[high] HARD-06 {s}:{d} TLS deshabilitado\n", .{ path, lineno });
            } else if (!has_warning) {
                try out(allocator, "[medium] HARD-05 {s}:{d} escape hatch sin aviso\n", .{ path, lineno });
            }
            findings += 1;
        }
        if (is_requirements and line.len > 0 and line[0] != '#' and
            std.mem.indexOf(u8, line, "==") == null)
        {
            try out(allocator, "[low] HARD-07 {s}:{d} sin fijar: {s}\n", .{ path, lineno, line });
            findings += 1;
        }
    }
    return findings;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    global_io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 2) {
        try out(allocator, "uso: scan_zig <fichero> [fichero...]\n", .{});
        std.process.exit(2);
    }

    var total: usize = 0;
    for (args[1..]) |path| {
        total += try scanFile(allocator, path);
    }
    try out(allocator, "hallazgos: {d}\n", .{total});
    if (total > 0) std.process.exit(1);
}

test "detecta patrones" {
    try std.testing.expect(containsAny("x = \"dev-secret-change-me\"", &forbidden));
    try std.testing.expect(!containsAny("x = 1", &forbidden));
}
