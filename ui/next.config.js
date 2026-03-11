/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Next 14+ static export mode (replaces `next export`).
  output: "export",
  trailingSlash: true,
  // Avoid Next guessing workspace root when multiple lockfiles exist on the host.
  outputFileTracingRoot: __dirname,
  images: {
    unoptimized: true,
  },
  // Suppress CSS chunk preload hints that cause "preloaded but not used" console
  // warnings. In static export mode Next.js preloads all CSS chunks in the shared
  // layout, but only the current page's styles are needed.
  experimental: {
    cssChunking: "strict",
  },
};

module.exports = nextConfig;
