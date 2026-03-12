import "./globals.css";

export const metadata = {
    title: "AI Malware Analysis Service",
    description: "Advanced Malware Behavioral Analysis",
};

export default function RootLayout({ children }) {
    return (
        <html lang="en">
            <body className="antialiased">{children}</body>
        </html>
    );
}