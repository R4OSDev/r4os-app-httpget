const r4os = @import("r4os");

const MAX_TCP_PAYLOAD: usize = r4os.abi.net_service_tcp_read_max;
const MAX_HTTP_RESPONSE: usize = 8192;
const MAX_REDIRECT_URL: usize = 256;
const RESPONSE_WAIT_MS: u64 = 3000;
const REDIRECT_LIMIT: usize = 3;
const DEFAULT_PORT: u16 = 80;

const Url = struct {
    original: []const u8,
    host: []const u8,
    path: []const u8,
    port: u16,
    target_ip: [4]u8,
    resolved: bool,
};

const App = struct {
    sys: r4os.r4sys.Context,
    net: r4os.r4net.Context,

    fn init(r4_app: *r4os.App) ?App {
        return .{
            .sys = r4_app.system(),
            .net = r4_app.networkLowLevel() orelse return null,
        };
    }

    fn argsRaw(self: *const App) [*:0]const u8 {
        return self.sys.argsRaw();
    }

    fn write(self: *const App, value: []const u8) void {
        self.sys.write(value);
    }

    fn putc(self: *const App, ch: u8) void {
        self.sys.putc(ch);
    }

    fn printU64(self: *const App, value: u64) void {
        self.sys.printU64(value);
    }

    fn ticksFromMilliseconds(self: *const App, ms: u64) u64 {
        return self.sys.ticksFromMilliseconds(ms);
    }

    fn fileWrite(self: *const App, path: [*:0]const u8, data: []const u8) i32 {
        return self.sys.fileWrite(path, data);
    }

    fn netDnsResolveService(self: *const App, name_value: []const u8, out: *[4]u8) i32 {
        return self.net.netDnsResolveService(name_value, out);
    }

    fn netDnsResultName(self: *const App, result: i32) []const u8 {
        return self.net.netDnsResultName(result);
    }

    fn tcpConnectService(self: *const App, a: u8, b: u8, c: u8, d: u8, port: u16) i32 {
        return self.net.tcpConnectService(a, b, c, d, port);
    }

    fn tcpWriteService(self: *const App, handle: u32, data: []const u8) i32 {
        return self.net.tcpWriteService(handle, data);
    }

    fn tcpReadAvailableWaitService(self: *const App, handle: u32, out: []u8, wait_ticks: u64) i32 {
        return self.net.tcpReadAvailableWaitService(handle, out, wait_ticks);
    }

    fn tcpCloseService(self: *const App, handle: u32) i32 {
        return self.net.tcpCloseService(handle);
    }
};

pub fn r4_app_main(r4_app: *r4os.App) i32 {
    const ctx = App.init(r4_app) orelse return r4os.abi.err_no_group;
    const args = trim(zSlice(ctx.argsRaw()));
    const first = takeToken(args) orelse {
        usage(&ctx);
        return 1;
    };
    const outfile_token = takeToken(first.rest);
    if (outfile_token != null and outfile_token.?.rest.len != 0) {
        usage(&ctx);
        return 1;
    }

    var response: [MAX_HTTP_RESPONSE]u8 = undefined;
    var redirect_buf: [MAX_REDIRECT_URL]u8 = undefined;
    var current_url = first.token;
    var redirects: usize = 0;

    while (true) {
        const url = parseUrl(&ctx, current_url) orelse {
            usage(&ctx);
            return 1;
        };
        if (url.resolved) {
            ctx.write("HTTPGET resolved ");
            ctx.write(url.host);
            ctx.write(" to ");
            writeIpv4(&ctx, url.target_ip);
            ctx.write("\r\n");
        }

        const total = fetchOnce(&ctx, url, response[0..]) orelse return 1;
        const response_bytes = response[0..total];
        printStatus(&ctx, response_bytes);
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
            current_url = resolveRedirectUrl(url, trim(location), redirect_buf[0..]) orelse {
                ctx.write("HTTPGET redirect: unsupported-location\r\n");
                return 1;
            };
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
            const saved = ctx.fileWrite(out_path, body);
            ctx.write("HTTPGET saved: ");
            if (saved >= 0) {
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
    ctx.write("Usage: HTTPGET http://host[:port]/path [outfile]\r\n");
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
    if (indexOfByte(host_port, ':')) |colon| {
        host = host_port[0..colon];
        port = parsePort(host_port[colon + 1 ..]) orelse return null;
    }
    if (host.len == 0) return null;

    var target_ip: [4]u8 = undefined;
    var resolved = false;
    if (parseIpv4(host)) |ip| {
        target_ip = ip;
    } else {
        const result = ctx.netDnsResolveService(host, &target_ip);
        if (result != r4os.abi.dns_result_ok) {
            ctx.write("HTTPGET resolve failed for ");
            ctx.write(host);
            ctx.write(": ");
            ctx.write(ctx.netDnsResultName(result));
            ctx.write("\r\n");
            return null;
        }
        resolved = true;
    }

    return .{
        .original = raw,
        .host = host,
        .path = path,
        .port = port,
        .target_ip = target_ip,
        .resolved = resolved,
    };
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
    const request = buildRequest(request_buf[0..], url) orelse {
        ctx.write("HTTPGET: request too large\r\n");
        return null;
    };

    ctx.write("HTTPGET connect ");
    writeIpv4(ctx, url.target_ip);
    ctx.write(":");
    ctx.printU64(url.port);
    ctx.write(": ");
    const conn = ctx.tcpConnectService(url.target_ip[0], url.target_ip[1], url.target_ip[2], url.target_ip[3], url.port);
    if (conn <= 0) {
        ctx.write("failed\r\n");
        return null;
    }
    ctx.write("ok\r\n");

    const conn_id: u32 = @intCast(conn);
    const written = ctx.tcpWriteService(conn_id, request);
    if (written < 0 or written != @as(i32, @intCast(request.len))) {
        ctx.write("HTTPGET write: failed\r\n");
        _ = ctx.tcpCloseService(conn_id);
        return null;
    }
    ctx.write("HTTPGET sent: ");
    ctx.printU64(@intCast(written));
    ctx.write("\r\n");

    var total: usize = 0;
    var read_buf: [MAX_TCP_PAYLOAD * 4]u8 = undefined;
    const response_wait_ticks = ctx.ticksFromMilliseconds(RESPONSE_WAIT_MS);
    while (total < response.len) {
        const read_cap = @min(read_buf.len, response.len - total);
        const got = ctx.tcpReadAvailableWaitService(conn_id, read_buf[0..read_cap], response_wait_ticks);
        if (got <= 0) break;
        const got_len: usize = @intCast(got);
        if (total + got_len > response.len) {
            ctx.write("HTTPGET response: too-large\r\n");
            _ = ctx.tcpCloseService(conn_id);
            return null;
        }
        @memcpy(response[total .. total + got_len], read_buf[0..got_len]);
        total += got_len;
        if (responseComplete(response[0..total])) break;
    }
    _ = ctx.tcpCloseService(conn_id);

    if (total == 0) {
        ctx.write("HTTPGET read: timeout\r\n");
        return null;
    }
    if (!responseComplete(response[0..total]) and total == response.len) {
        ctx.write("HTTPGET response: too-large\r\n");
        return null;
    }
    if (contentLength(response[0..total])) |expected| {
        const body = responseBody(response[0..total]);
        if (body.len < expected) {
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

const Token = struct {
    token: []const u8,
    rest: []const u8,
};

fn takeToken(value: []const u8) ?Token {
    const trimmed = trim(value);
    if (trimmed.len == 0) return null;
    var end: usize = 0;
    while (end < trimmed.len and !isSpace(trimmed[end])) : (end += 1) {}
    return .{
        .token = trimmed[0..end],
        .rest = if (end >= trimmed.len) "" else trim(trimmed[end..]),
    };
}

fn parsePort(value: []const u8) ?u16 {
    if (value.len == 0) return null;
    var out: u32 = 0;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return null;
        out = out * 10 + @as(u32, ch - '0');
        if (out == 0 or out > 65535) return null;
    }
    return @intCast(out);
}

fn parseU16(value: []const u8) ?u16 {
    if (value.len == 0) return null;
    var out: u32 = 0;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return null;
        out = out * 10 + @as(u32, ch - '0');
        if (out > 65535) return null;
    }
    return @intCast(out);
}

fn parseUsize(value: []const u8) ?usize {
    if (value.len == 0) return null;
    var out: usize = 0;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return null;
        out = out * 10 + @as(usize, ch - '0');
    }
    return out;
}

fn parseIpv4(value: []const u8) ?[4]u8 {
    var out: [4]u8 = .{0} ** 4;
    var part: usize = 0;
    var accum: u16 = 0;
    var digits: usize = 0;

    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        const ch = value[index];
        if (ch >= '0' and ch <= '9') {
            accum = accum * 10 + @as(u16, ch - '0');
            if (accum > 255) return null;
            digits += 1;
            if (digits > 3) return null;
        } else if (ch == '.') {
            if (digits == 0 or part >= 3) return null;
            out[part] = @intCast(accum);
            part += 1;
            accum = 0;
            digits = 0;
        } else {
            return null;
        }
    }
    if (digits == 0 or part != 3) return null;
    out[part] = @intCast(accum);
    return out;
}

fn writeIpv4(ctx: *const App, ip: [4]u8) void {
    ctx.printU64(ip[0]);
    ctx.putc('.');
    ctx.printU64(ip[1]);
    ctx.putc('.');
    ctx.printU64(ip[2]);
    ctx.putc('.');
    ctx.printU64(ip[3]);
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
