import type { NextConfig } from "next";

// Static, path-independent security headers. The Content-Security-Policy is not here: it needs a
// fresh nonce per request, so it is set in src/proxy.ts (src/lib/security/csp.ts) instead.
const SECURITY_HEADERS = [
  // This app renders no third-party frame content and is never meant to be framed itself
  // (`frame-ancestors 'none'` in the CSP already says the same to modern browsers; this is the
  // header older ones still read).
  { key: "X-Frame-Options", value: "DENY" },
  // Stops a browser from guessing a response's type from its content (for example treating an
  // uploaded-looking file as executable script).
  { key: "X-Content-Type-Options", value: "nosniff" },
  // Sends the full URL only to this app's own pages; a cross-origin link gets just the origin, so
  // no path, query string or fragment (which can carry a token or a search term) ever leaks out.
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  // Nothing in ArcRadar asks for the camera, microphone, geolocation, USB or payment APIs; refusing
  // them at the browser closes off an embedded-frame or dependency abusing one silently.
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), usb=(), payment=(), interest-cohort=()",
  },
  ...(process.env.NODE_ENV === "production"
    ? [
        // Tells the browser to only ever speak https to this origin from now on. Safe to send only
        // in production: browsers ignore this header entirely when it arrives over plain http (as
        // local dev and the local nginx proxy always do), so it could not do anything there anyway.
        {
          key: "Strict-Transport-Security",
          value: "max-age=63072000; includeSubDomains; preload",
        },
      ]
    : []),
];

const nextConfig: NextConfig = {
  async headers() {
    return [{ source: "/(.*)", headers: SECURITY_HEADERS }];
  },
};

export default nextConfig;
