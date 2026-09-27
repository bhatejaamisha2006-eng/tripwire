import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Tripwire — Agent Security Runtime",
  description: "Adversarial agent playground and live security monitor",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
