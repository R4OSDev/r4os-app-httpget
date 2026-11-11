const std = @import("std");
const r4os = @import("r4os");

const MAX_TCP_PAYLOAD: usize = r4os.abi.net_service_tcp_read_max;
const MAX_HTTP_RESPONSE: usize = 8192;
const MAX_REDIRECT_URL: usize = 256;
const REDIRECT_LIMIT: usize = 3;
const DEFAULT_PORT: u16 = 80;

const Url = struct {
    original: []const u8,
    host: []const u8,
    path: []const u8,
    port: u16,
    target: r4os.abi.NetworkEndpoint,
    resolved: bool,
};

const App = struct {
    sys: r4os.r4sys.Context,
    output: *r4os.launch_io.Output,
    network: *r4os.network_stream.Session,
    budget: *r4os.rpc_budget.Budget,
    args: []const u8,
    family: u32,

    fn write(self: *const App, value: []const u8) void {
        self.output.write(value);
    }
    fn printU64(self: *const App, value: u64) void {
        self.output.number(value);
    }
};

pub fn r4_app_main(app: *r4os.App2) i32 {
    var output: r4os.launch_io.Output = undefined;
    if (r4os.launch_io.Output.init(app, &output) != 0) return 1;
    var selected_family: u32 = 0;
    const args = r4os.network_stream.arguments(app.args(), &selected_family) orelse {
        output.write("HTTPGET: invalid argument grammar\r\n");
        _ = output.close();
        return 1;
    };
    var budget = r4os.rpc_budget.Budget.fromTimeout(output.clock.read, .{ .kind = 1, .nanoseconds = 10_000_000_000 }) catch {
        _ = output.close();
        return 1;
    };
    var network: r4os.network_stream.Session = undefined;
    const opened = r4os.network_stream.Session.open(app, &budget, &network);
    if (opened != 0) {
        output.write("HTTPGET: TCPSVC unavailable or invalid\r\n");
        _ = output.close();
        return 1;
    }
    const ctx: App = .{ .sys = app.system(), .output = &output, .network = &network, .budget = &budget, .args = args, .family = selected_family };
    const result = run(&ctx);
    const closed = network.close();
    if (closed != 0) output.write("HTTPGET close: not confirmed\r\n");
    const io_closed = output.close();
    return if (output.failed or closed != 0 or io_closed != 0) 1 else result;
}

fn run(ctx: *const App) i32 {
    const args = trim(ctx.args);
    const first = takeToken(args) orelse {
        usage(ctx);
        return 1;
    };
    const outfile_token = takeToken(first.rest);
    if (outfile_token != null and outfile_token.?.rest.len != 0) {
        usage(ctx);
        return 1;
    }

    var response: [MAX_HTTP_RESPONSE]u8 = undefined;
    var redirect_buf: [MAX_REDIRECT_URL]u8 = undefined;
    var current_url = first.token;
    var redirects: usize = 0;

    while (true) {
        const url = parseUrl(ctx, current_url) orelse {
            usage(ctx);
            return 1;
        };
        if (url.resolved) {
            ctx.write("HTTPGET resolved ");
            ctx.write(url.host);
            ctx.write(" to ");
            writeAddress(ctx, url.target.address);
            ctx.write("\r\n");
        }

        const total = fetchOnce(ctx, url, response[0..]) orelse return 1;
        const response_bytes = response[0..total];
        printStatus(ctx, response_bytes);
        const code = statusCode(response_bytes);

        if (isRedirectStatus(code)) {
            if (redirects >= REDIRECT_LIMIT) {
                ctx.write("HTTPGET redirect: too-many\r\n");
                return 1;
            }
            const location = responseHeader(response_bytes, "Location") orelse {
                ctx.write("HTTPGET redirect: missing-location\r\n");
                return 1;
            };
            var next_url: [MAX_REDIRECT_URL]u8 = undefined;
            const redirected = resolveRedirectUrl(url, trim(location), &next_url) orelse {
                ctx.write("HTTPGET redirect: unsupported-location\r\n");
                return 1;
            };
            @memcpy(redirect_buf[0..redirected.len], redirected);
            current_url = redirect_buf[0..redirected.len];
            redirects += 1;
            ctx.write("HTTPGET redirect: ");
            ctx.write(current_url);
            ctx.write("\r\n");
            continue;
        }

        const body = responseBodyLimited(response_bytes);
        ctx.write("HTTPGET body-bytes: ");
        ctx.printU64(body.len);
        ctx.write("\r\n");
        ctx.write("HTTPGET body:\r\n");
        ctx.write(body);
        if (body.len == 0 or body[body.len - 1] != '\n') ctx.write("\r\n");

        if (outfile_token) |out_tok| {
            var path_buf: [128:0]u8 = .{0} ** 128;
            const out_path = copyZ(path_buf[0..], out_tok.token) orelse {
                ctx.write("HTTPGET save: path-too-long\r\n");
                return 1;
            };
            const files = r4os.Files{ .sys = ctx.sys };
            const saved: i32 = switch (files.write(.{ .ptr = out_path, .len = @intCast(out_tok.token.len) }, body)) {
                .bytes => |count| @intCast(count),
                .end => 0,
                .failure => |code_value| code_value,
            };
            ctx.write("HTTPGET saved: ");
            if (saved >= 0 and saved == body.len) {
                ctx.printU64(@intCast(saved));
                ctx.write(" bytes to ");
                ctx.write(out_tok.token);
                ctx.write("\r\n");
            } else {
                ctx.write("failed\r\n");
                return 1;
            }
        }

        return if (isHttpOkStatus(code)) 0 else 1;
    }
}

fn usage(ctx: *const App) void {
    ctx.write("Usage: HTTPGET [-4|-6] http://host[:port]/path [outfile]\r\n");
}

fn parseUrl(ctx: *const App, raw: []const u8) ?Url {
    if (startsWithIgnoreCase(raw, "https://")) {
        ctx.write("HTTPGET: https is not supported\r\n");
        return null;
    }

    const without_scheme = if (startsWithIgnoreCase(raw, "http://")) raw[7..] else raw;
    const slash = indexOfByte(without_scheme, '/') orelse without_scheme.len;
    const host_port = without_scheme[0..slash];
    if (host_port.len == 0) return null;
    const path = if (slash < without_scheme.len) without_scheme[slash..] else "/";

    var host = host_port;
    var port: u16 = DEFAULT_PORT;
    if (host_port[0] == '[') {
        const close = indexOfByte(host_port, ']') orelse return null;
        host = host_port[0 .. close + 1];
        if (close + 1 < host_port.len) {
            if (host_port[close + 1] != ':') return null;
            port = parsePort(host_port[close + 2 ..]) orelse return null;
        }
    } else if (indexOfByte(host_port, ':')) |colon| {
        host = host_port[0..colon];
        port = parsePort(host_port[colon + 1 ..]) orelse return null;
    }
    if (host.len == 0 or std.mem.indexOfAny(u8, host, " \t\r\n@") != null) return null;
    var target: r4os.abi.NetworkEndpoint = .{};
    const rc = ctx.network.resolve(host, port, ctx.family, ctx.budget, &target);
    if (rc != 0) {
        ctx.write("HTTPGET resolve failed for ");
        ctx.write(host);
        ctx.write("\r\n");
        return null;
    }
    const numeric = if (host[0] == '[') host[1 .. host.len - 1] else host;
    return .{ .original = raw, .host = host, .path = path, .port = port, .target = target, .resolved = r4os.network_family.parseAddress(numeric) == null };
}

fn buildRequest(out: []u8, url: Url) ?[]const u8 {
    var len: usize = 0;
    if (!append(out, &len, "GET ")) return null;
    if (!append(out, &len, url.path)) return null;
    if (!append(out, &len, " HTTP/1.0\r\nHost: ")) return null;
    if (!append(out, &len, url.host)) return null;
    if (url.port != DEFAULT_PORT) {
        if (!append(out, &len, ":")) return null;
        if (!appendPort(out, &len, url.port)) return null;
    }
    if (!append(out, &len, "\r\nConnection: close\r\nUser-Agent: R4OS-HTTPGET/0.17\r\n\r\n")) return null;
    return out[0..len];
}

fn fetchOnce(ctx: *const App, url: Url, response: []u8) ?usize {
    var request_buf: [MAX_TCP_PAYLOAD]u8 = undefined;
    const request = buildRequest(&request_buf, url) orelse {
        ctx.write("HTTPGET: request too large\r\n");
        return null;
    };
    ctx.write("HTTPGET connect ");
    writeAddress(ctx, url.target.address);
    ctx.write(":");
    ctx.printU64(url.port);
    ctx.write(": ");
    var socket: r4os.network_stream.Socket = undefined;
    if (ctx.network.create(url.target, false, ctx.budget, &socket) != 0) {
        ctx.write("failed\r\n");
        return null;
    }
    defer socket.close();
    ctx.write("ok\r\n");
    const written = socket.writeAll(request, ctx.budget) catch return null;
    if (!r4os.network_stream.complete(written)) {
        ctx.write("HTTPGET write: failed prefix=");
        ctx.printU64(written.bytes);
        ctx.write("\r\n");
        return null;
    }
    ctx.write("HTTPGET sent: ");
    ctx.printU64(written.bytes);
    ctx.write("\r\n");
    var reader: r4os.network_stream.Reader = .{ .socket = &socket };
    var total: usize = 0;
    var eof = false;
    while (total < response.len) {
        const got = reader.read(response[total..], false, ctx.budget) catch return null;
        total += @intCast(got.bytes);
        const outcome: r4os.stream_transfer.Outcome = @enumFromInt(got.outcome);
        if (outcome == .eof) eof = true;
        if (outcome != .pending and outcome != .complete and outcome != .eof and outcome != .would_block) {
            ctx.write("HTTPGET read: ");
            ctx.write(@tagName(outcome));
            ctx.write(" prefix=");
            ctx.printU64(total);
            ctx.write("\r\n");
            return null;
        }
        if (responseComplete(response[0..total]) or eof) break;
    }
    const received = response[0..total];
    if (headerEnd(received) == null or statusCode(received) == null) {
        ctx.write("HTTPGET response: incomplete\r\n");
        return null;
    }
    if (responseHeader(received, "Transfer-Encoding") != null) {
        ctx.write("HTTPGET response: unsupported transfer encoding\r\n");
        return null;
    }
    if (responseHeader(received, "Content-Length") != null and contentLength(received) == null) {
        ctx.write("HTTPGET response: invalid content length\r\n");
        return null;
    }
    if (!responseComplete(received) and !eof) {
        ctx.write("HTTPGET response: too-large\r\n");
        return null;
    }
    if (contentLength(received)) |expected| {
        if (responseBody(received).len < expected) {
            ctx.write("HTTPGET response: incomplete\r\n");
            return null;
        }
    }
    ctx.write("HTTPGET received: ");
    ctx.printU64(total);
    ctx.write("\r\n");
    return total;
}

fn printStatus(ctx: *const App, response: []const u8) void {
    ctx.write("HTTPGET status: ");
    const line_end = findHeaderLineEnd(response) orelse response.len;
    ctx.write(response[0..line_end]);
    ctx.write("\r\n");
}

fn isHttpOkStatus(code: ?u16) bool {
    const value = code orelse return false;
    return value >= 200 and value < 300;
}

fn isRedirectStatus(code: ?u16) bool {
    const value = code orelse return false;
    return value == 301 or value == 302 or value == 303 or value == 307 or value == 308;
}

fn statusCode(response: []const u8) ?u16 {
    const line_end = findHeaderLineEnd(response) orelse response.len;
    const line = response[0..line_end];
    const first_space = indexOfByte(line, ' ') orelse return null;
    var start = first_space + 1;
    while (start < line.len and line[start] == ' ') : (start += 1) {}
    var end = start;
    while (end < line.len and line[end] >= '0' and line[end] <= '9') : (end += 1) {}
    if (end == start) return null;
    return parseU16(line[start..end]);
}

fn responseBody(response: []const u8) []const u8 {
    if (indexOf(response, "\r\n\r\n")) |pos| return response[pos + 4 ..];
    if (indexOf(response, "\n\n")) |pos| return response[pos + 2 ..];
    return "";
}

fn responseBodyLimited(response: []const u8) []const u8 {
    const body = responseBody(response);
    const expected = contentLength(response) orelse return body;
    if (body.len <= expected) return body;
    return body[0..expected];
}

fn responseComplete(response: []const u8) bool {
    const body = responseBody(response);
    if (body.len == 0 and headerEnd(response) == null) return false;
    if (contentLength(response)) |expected| return body.len >= expected;
    return false;
}

fn headerEnd(response: []const u8) ?usize {
    if (indexOf(response, "\r\n\r\n")) |pos| return pos + 4;
    if (indexOf(response, "\n\n")) |pos| return pos + 2;
    return null;
}

fn contentLength(response: []const u8) ?usize {
    const value = responseHeader(response, "Content-Length") orelse return null;
    return parseUsize(trim(value));
}

fn responseHeader(response: []const u8, name: []const u8) ?[]const u8 {
    const end = headerEnd(response) orelse return null;
    var offset: usize = 0;
    while (offset < end) {
        const line_end = findHeaderLineEnd(response[offset..end]) orelse end - offset;
        const line = response[offset .. offset + line_end];
        if (headerNameMatches(line, name)) {
            return trim(line[name.len + 1 ..]);
        }
        offset += line_end;
        while (offset < end and (response[offset] == '\r' or response[offset] == '\n')) : (offset += 1) {}
    }
    return null;
}

fn headerNameMatches(line: []const u8, name: []const u8) bool {
    if (line.len <= name.len or line[name.len] != ':') return false;
    return startsWithIgnoreCase(line[0..name.len], name);
}

fn resolveRedirectUrl(base: Url, location: []const u8, out: []u8) ?[]const u8 {
    if (startsWithIgnoreCase(location, "https://")) return null;
    if (startsWithIgnoreCase(location, "http://")) return copyText(out, location);
    if (location.len == 0) return null;

    var len: usize = 0;
    if (!append(out, &len, "http://")) return null;
    if (!append(out, &len, base.host)) return null;
    if (base.port != DEFAULT_PORT) {
        if (!append(out, &len, ":")) return null;
        if (!appendPort(out, &len, base.port)) return null;
    }

    if (location[0] == '/') {
        if (!append(out, &len, location)) return null;
    } else {
        const prefix_len = parentPathLen(base.path);
        if (!append(out, &len, base.path[0..prefix_len])) return null;
        if (!append(out, &len, location)) return null;
    }
    return out[0..len];
}

fn parentPathLen(path: []const u8) usize {
    var i = path.len;
    while (i > 0) {
        i -= 1;
        if (path[i] == '/') return i + 1;
    }
    return 1;
}

fn findHeaderLineEnd(value: []const u8) ?usize {
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        if (value[i] == '\r' or value[i] == '\n') return i;
    }
    return null;
}

fn append(out: []u8, len: *usize, text: []const u8) bool {
    if (len.* + text.len > out.len) return false;
    @memcpy(out[len.* .. len.* + text.len], text);
    len.* += text.len;
    return true;
}

fn appendPort(out: []u8, len: *usize, port: u16) bool {
    var digits: [5]u8 = undefined;
    var value: u16 = port;
    var count: usize = 0;
    while (true) {
        digits[digits.len - 1 - count] = @intCast('0' + (value % 10));
        count += 1;
        value /= 10;
        if (value == 0) break;
    }
    return append(out, len, digits[digits.len - count ..]);
}

const Token = struct { token: []const u8, rest: []const u8 };
fn takeToken(value: []const u8) ?Token {
    var failure: r4os.arguments.Failure = .{};
    var cursor = r4os.arguments.ArgCursor.init(value, .{}, &failure) catch return null;
    const token = (cursor.next() catch return null) orelse return null;
    return .{ .token = token.bytes(value) catch return null, .rest = cursor.remainingArguments() catch return null };
}

fn parsePort(value: []const u8) ?u16 {
    if (value.len == 0) return null;
    for (value) |byte| if (byte < '0' or byte > '9') return null;
    const number = std.fmt.parseInt(u16, value, 10) catch return null;
    return if (number == 0) null else number;
}

fn parseU16(value: []const u8) ?u16 {
    if (value.len == 0) return null;
    for (value) |byte| if (byte < '0' or byte > '9') return null;
    const number = std.fmt.parseInt(u16, value, 10) catch return null;
    return number;
}

fn parseUsize(value: []const u8) ?usize {
    if (value.len == 0) return null;
    for (value) |byte| if (byte < '0' or byte > '9') return null;
    const number = std.fmt.parseInt(usize, value, 10) catch return null;
    return number;
}

fn writeAddress(ctx: *const App, address: r4os.abi.NetworkAddress) void {
    var buffer: [80]u8 = undefined;
    ctx.write(r4os.network_family.addressText(&buffer, address) catch "unknown");
}

fn copyZ(out: [:0]u8, text: []const u8) ?[*:0]const u8 {
    if (text.len >= out.len) return null;
    @memcpy(out[0..text.len], text);
    out[text.len] = 0;
    return @ptrCast(out.ptr);
}

fn copyText(out: []u8, text: []const u8) ?[]const u8 {
    if (text.len > out.len) return null;
    @memcpy(out[0..text.len], text);
    return out[0..text.len];
}

fn indexOfByte(value: []const u8, needle: u8) ?usize {
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        if (value[i] == needle) return i;
    }
    return null;
}

fn indexOf(value: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or needle.len > value.len) return null;
    var i: usize = 0;
    while (i + needle.len <= value.len) : (i += 1) {
        if (bytesEqual(value[i .. i + needle.len], needle)) return i;
    }
    return null;
}

fn bytesEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn startsWithIgnoreCase(value: []const u8, prefix: []const u8) bool {
    if (value.len < prefix.len) return false;
    var i: usize = 0;
    while (i < prefix.len) : (i += 1) {
        if (asciiUpper(value[i]) != asciiUpper(prefix[i])) return false;
    }
    return true;
}

fn asciiUpper(ch: u8) u8 {
    if (ch >= 'a' and ch <= 'z') return ch - 32;
    return ch;
}

fn zSlice(ptr: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (ptr[len] != 0) : (len += 1) {}
    return ptr[0..len];
}

fn trim(value: []const u8) []const u8 {
    var start: usize = 0;
    var end = value.len;
    while (start < end and isSpace(value[start])) : (start += 1) {}
    while (end > start and isSpace(value[end - 1])) : (end -= 1) {}
    return value[start..end];
}

fn isSpace(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n';
}

test "migration HTTP distinguishes known length completion EOF and invalid lengths" {
    const short = "HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nabc";
    try std.testing.expect(!responseComplete(short));
    try std.testing.expectEqual(@as(usize, 9), contentLength(short).?);
    const full = "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    try std.testing.expect(responseComplete(full));
    try std.testing.expectEqualStrings("abc", responseBodyLimited(full));
    try std.testing.expect(contentLength("HTTP/1.0 200 OK\r\nContent-Length: 9999999999999999999999999999999\r\n\r\n") == null);
    try std.testing.expect(parsePort("65536") == null);
    try std.testing.expect(parsePort("0") == null);
}
