// src/MatrixRain.jsx
// Animated matrix-rain background used on the login screen.
import { useMemo } from "react";

const CHAR_SETS = [
  "01",
  "0123456789ABCDEF",
  "01アイウエオカキクケコ",
  "ALERT BREACH THREAT INTRUSION MALWARE",
  "01001101 10110010 01110010 11010011",
  "█▓▒░╔╗╚╝║═",
  "RSA AES SSL VPN IDS IPS",
  "255.255.255.0 192.168.1.1 ::1",
  "λ=∑∫∂√π∞≠≈≤≥",
  "FATAL CRIT WARN ERROR FAIL DENY",
  "SHA256 MD5 ECDSA HMAC JWT",
  "TCP UDP ICMP HTTP DNS SSH",
  "root admin sys kern daemon",
  "0xDEAD 0xBEEF 0xCAFE 0xF00D",
  "chmod 755 exec fork kill sudo su",
  "SYN ACK FIN RST PSH URG",
  "\\\\x1b[31m \\\\x1b[32m \\\\x1b[0m",
  "XSS SSRF RCE LFI IDOR CSRF OWASP",
];

export default function MatrixRain() {
  const columns = useMemo(() => {
    return CHAR_SETS.map((chars, i) => (
      <div
        key={i}
        className="admin-matrix-column"
        style={{
          left: `${(i / CHAR_SETS.length) * 100}%`,
          animationDuration: `${10 + Math.random() * 14}s`,
          animationDelay: `${Math.random() * -20}s`,
          fontSize: `${11 + Math.floor(Math.random() * 4)}px`,
          opacity: 0.3 + Math.random() * 0.7,
          transition: "all 0.3s ease",
        }}
      >
        {chars}
      </div>
    ));
  }, []);

  return <div className="admin-matrix-rain">{columns}</div>;
}