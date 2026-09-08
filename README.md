# Construct Accounts

The identity service: an OAuth 2.0 / OIDC-style provider with password and passkey sign-in, sessions, organisations, and the `cat_*` identity tokens every other service validates. Go, MySQL. Sends its mail through Construct Delivery.

Part of [Construct](https://github.com/construct-space), the platform behind construct.space, published as it ran in September 2026. The organisation README maps the other services.

## Run

```
go run .
```

Copy `.env.sample` to `.env` and fill in the values; secrets are marked `change-me`.
A `Dockerfile` and a `captain-definition` are included: the service ran on CapRover.

## License

MIT, see `LICENSE`.