# ============================================================================
# test_url.mojo — Tests for URL Parser
# ============================================================================

from url import Url, parse_url


# ============================================================================
# Test Helpers
# ============================================================================


def assert_str_eq(actual: String, expected: String, label: String) raises:
    if actual != expected:
        raise Error(
            label + ": expected '" + expected + "', got '" + actual + "'"
        )


def assert_int_eq(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(
            label + ": expected " + String(expected) + ", got " + String(actual)
        )


# ============================================================================
# Tests
# ============================================================================


fn test_simple_http() raises:
    var url = parse_url("http://example.com")
    assert_str_eq(url.scheme, "http", "scheme")
    assert_str_eq(url.host, "example.com", "host")
    assert_int_eq(url.port, 80, "port")
    assert_str_eq(url.path, "/", "path")
    assert_str_eq(url.query, "", "query")
    assert_str_eq(url.request_path(), "/", "request_path")


fn test_http_with_path() raises:
    var url = parse_url("http://example.com/api/data")
    assert_str_eq(url.scheme, "http", "scheme")
    assert_str_eq(url.host, "example.com", "host")
    assert_int_eq(url.port, 80, "port")
    assert_str_eq(url.path, "/api/data", "path")
    assert_str_eq(url.query, "", "query")
    assert_str_eq(url.request_path(), "/api/data", "request_path")


fn test_http_with_query() raises:
    var url = parse_url("http://example.com/search?q=mojo&lang=en")
    assert_str_eq(url.scheme, "http", "scheme")
    assert_str_eq(url.host, "example.com", "host")
    assert_str_eq(url.path, "/search", "path")
    assert_str_eq(url.query, "q=mojo&lang=en", "query")
    assert_str_eq(url.request_path(), "/search?q=mojo&lang=en", "request_path")


fn test_custom_port() raises:
    var url = parse_url("http://example.com:8080/api")
    assert_str_eq(url.host, "example.com", "host")
    assert_int_eq(url.port, 8080, "port")
    assert_str_eq(url.path, "/api", "path")


fn test_https_default_port() raises:
    var url = parse_url("https://example.com/secure")
    assert_str_eq(url.scheme, "https", "scheme")
    assert_str_eq(url.host, "example.com", "host")
    assert_int_eq(url.port, 443, "port")
    assert_str_eq(url.path, "/secure", "path")


fn test_https_custom_port() raises:
    var url = parse_url("https://example.com:8443/secure")
    assert_str_eq(url.scheme, "https", "scheme")
    assert_int_eq(url.port, 8443, "port")


fn test_trailing_slash() raises:
    var url = parse_url("http://example.com/")
    assert_str_eq(url.path, "/", "path")


fn test_query_no_path() raises:
    var url = parse_url("http://example.com?key=value")
    assert_str_eq(url.path, "/", "path")
    assert_str_eq(url.query, "key=value", "query")


fn test_host_header_standard_port() raises:
    var url = parse_url("http://example.com/path")
    assert_str_eq(url.host_header(), "example.com", "host_header standard")


fn test_host_header_custom_port() raises:
    var url = parse_url("http://example.com:9090/path")
    assert_str_eq(url.host_header(), "example.com:9090", "host_header custom")


fn test_raw_preserved() raises:
    var raw = "http://example.com:8080/api?q=1"
    var url = parse_url(raw)
    assert_str_eq(url.raw, raw, "raw")


fn test_missing_scheme_raises() raises:
    var raised = False
    try:
        _ = parse_url("example.com/path")
    except:
        raised = True
    if not raised:
        raise Error("expected error for missing scheme")


fn test_unsupported_scheme_raises() raises:
    var raised = False
    try:
        _ = parse_url("ftp://example.com/file")
    except:
        raised = True
    if not raised:
        raise Error("expected error for unsupported scheme")


fn test_deep_path() raises:
    var url = parse_url("http://api.example.com/v1/users/123/posts")
    assert_str_eq(url.host, "api.example.com", "host")
    assert_str_eq(url.path, "/v1/users/123/posts", "path")


fn test_ip_host() raises:
    var url = parse_url("http://127.0.0.1:3000/health")
    assert_str_eq(url.host, "127.0.0.1", "host")
    assert_int_eq(url.port, 3000, "port")
    assert_str_eq(url.path, "/health", "path")


# ============================================================================
# Security Validation Tests
# ============================================================================


fn test_port_zero_rejected() raises:
    """Port 0 should be rejected."""
    var raised = False
    try:
        _ = parse_url("http://example.com:0/path")
    except:
        raised = True
    if not raised:
        raise Error("expected error for port 0")


fn test_port_too_large_rejected() raises:
    """Port > 65535 should be rejected."""
    var raised = False
    try:
        _ = parse_url("http://example.com:99999/path")
    except:
        raised = True
    if not raised:
        raise Error("expected error for port 99999")


fn test_port_overflow_rejected() raises:
    """Very large port number should be rejected (overflow prevention)."""
    var raised = False
    try:
        _ = parse_url("http://example.com:999999999/path")
    except:
        raised = True
    if not raised:
        raise Error("expected error for overflowing port")


fn test_host_with_space_rejected() raises:
    """Hostname with space should be rejected."""
    var raised = False
    try:
        _ = parse_url("http://evil .com/path")
    except:
        raised = True
    if not raised:
        raise Error("expected error for host with space")


# ============================================================================
# WebSocket Scheme Tests
# ============================================================================


fn test_ws_scheme() raises:
    """WebSocket ws:// should parse with port 80 default."""
    var url = parse_url("ws://echo.example.com/ws")
    assert_str_eq(url.scheme, "ws", "scheme")
    assert_str_eq(url.host, "echo.example.com", "host")
    assert_int_eq(url.port, 80, "port")
    assert_str_eq(url.path, "/ws", "path")


fn test_wss_scheme() raises:
    """Secure WebSocket wss:// should parse with port 443 default."""
    var url = parse_url("wss://echo.example.com/ws")
    assert_str_eq(url.scheme, "wss", "scheme")
    assert_str_eq(url.host, "echo.example.com", "host")
    assert_int_eq(url.port, 443, "port")
    assert_str_eq(url.path, "/ws", "path")


fn test_ws_custom_port() raises:
    """WebSocket ws:// with custom port."""
    var url = parse_url("ws://localhost:8080/chat")
    assert_str_eq(url.scheme, "ws", "scheme")
    assert_str_eq(url.host, "localhost", "host")
    assert_int_eq(url.port, 8080, "port")
    assert_str_eq(url.path, "/chat", "path")
    assert_str_eq(url.host_header(), "localhost:8080", "host_header")


fn test_wss_standard_port_host_header() raises:
    """Secure WebSocket on port 443 should not include port in host header."""
    var url = parse_url("wss://echo.example.com/ws")
    assert_str_eq(url.host_header(), "echo.example.com", "host_header")


# ============================================================================
# Test Runner
# ============================================================================


def run_test[test_fn: fn () raises -> None](
    name: String, mut passed: Int, mut failed: Int
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


def main() raises:
    var passed = 0
    var failed = 0

    print("=== URL Parser Tests ===")
    print()

    run_test[test_simple_http]("simple http", passed, failed)
    run_test[test_http_with_path]("http with path", passed, failed)
    run_test[test_http_with_query]("http with query", passed, failed)
    run_test[test_custom_port]("custom port", passed, failed)
    run_test[test_https_default_port]("https default port", passed, failed)
    run_test[test_https_custom_port]("https custom port", passed, failed)
    run_test[test_trailing_slash]("trailing slash", passed, failed)
    run_test[test_query_no_path]("query no path", passed, failed)
    run_test[test_host_header_standard_port](
        "host header standard port", passed, failed
    )
    run_test[test_host_header_custom_port](
        "host header custom port", passed, failed
    )
    run_test[test_raw_preserved]("raw preserved", passed, failed)
    run_test[test_missing_scheme_raises](
        "missing scheme raises", passed, failed
    )
    run_test[test_unsupported_scheme_raises](
        "unsupported scheme raises", passed, failed
    )
    run_test[test_deep_path]("deep path", passed, failed)
    run_test[test_ip_host]("ip host", passed, failed)

    # Security validation tests
    run_test[test_port_zero_rejected]("port 0 rejected", passed, failed)
    run_test[test_port_too_large_rejected](
        "port too large rejected", passed, failed
    )
    run_test[test_port_overflow_rejected](
        "port overflow rejected", passed, failed
    )
    run_test[test_host_with_space_rejected](
        "host with space rejected", passed, failed
    )

    # WebSocket scheme tests
    run_test[test_ws_scheme]("ws scheme", passed, failed)
    run_test[test_wss_scheme]("wss scheme", passed, failed)
    run_test[test_ws_custom_port]("ws custom port", passed, failed)
    run_test[test_wss_standard_port_host_header](
        "wss standard port host header", passed, failed
    )

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
