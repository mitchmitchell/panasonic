# kxprov-api

Shared Unix-socket API types and client for `kxprovd`. The daemon enforces [`Scope`] from
SO_PEERCRED locally (v2.3); this crate does not carry trust metadata from the gateway.
