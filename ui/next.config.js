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
};

module.exports = nextConfig;
