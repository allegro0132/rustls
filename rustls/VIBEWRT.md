Based on upstream rustls 0.23.46 at f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb.
The VibeWrt superproject imports this fork as a pinned Git submodule. Original Apache-2.0/ISC/MIT licenses are retained.
Original crate checksum: 48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf.

Local changes affect client configuration/handshake handling, SCT message decoding and the CommonState SCT accessor:
- Optional explicit ClientHello extension preference for actually present extensions. Default randomized order is unchanged. Unknown extensions follow numerically; ECH/PSK special suffix placement remains in the existing encoder.
- Resumption::disabled_without_tickets() uses NoClientSessionStorage and omits TLS1.3 PSK-mode/ticket-request extensions. Existing disabled() keeps upstream behavior.
- Optional empty RFC 5746 renegotiation_info instead of SCSV for clients offering TLS1.2. This does not enable renegotiation.

Only the router compatible profile selects these options. This fork has been exercised with ordinary TLS and HelloRetryRequest; ECH and QUIC profile interactions have not been qualified. No raw post-serialization ClientHello rewriting is performed: the handshake transcript uses the actual serialized message.
