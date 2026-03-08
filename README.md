# url — Pure Mojo URL Parser

A pure-[Mojo](https://www.modular.com/mojo) URL parser for HTTP client use.

## Features

- Parses scheme, host, port, path, and query string
- Handles `http://` and `https://` schemes
- Infers default ports (80 for HTTP, 443 for HTTPS)
- No external dependencies — pure string manipulation

## Usage

```mojo
from url import parse_url, Url

var u = parse_url("https://api.example.com/v1/data?key=val")
print(u.scheme)  # "https"
print(u.host)    # "api.example.com"
print(u.port)    # 443
print(u.path)    # "/v1/data"
print(u.query)   # "key=val"
```

## Requirements

- Mojo `>=0.26.1`
- No external packages

## Testing

```bash
pixi run test-url
# 23/23 tests pass
```

## License

MIT — see [LICENSE](LICENSE)
