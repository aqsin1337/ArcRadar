// Verifies the WCAG contrast of the design tokens in src/app/globals.css (both themes).
//   Text pairs need 4.5:1, UI boundaries (inputs, focus ring) need 3:1.
// Usage: npm run check:contrast
import { readFileSync } from "node:fs";

// CONTRAST_CSS lets tests point the script at another stylesheet.
const css = readFileSync(
  process.env.CONTRAST_CSS ?? new URL("../src/app/globals.css", import.meta.url),
  "utf8",
);

function readTheme(selectorPattern) {
  const block = new RegExp(`${selectorPattern}\\s*\\{([^}]*)\\}`).exec(css);
  if (!block) throw new Error(`Theme block not found: ${selectorPattern}`);
  const vars = {};
  for (const [, name, value] of block[1].matchAll(/--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;/g)) {
    vars[name] = value;
  }
  return vars;
}

const themes = {
  dark: readTheme(String.raw`:root,\s*\[data-theme="dark"\]`),
  light: readTheme(String.raw`\[data-theme="light"\]`),
};

const channel = (hex, i) => parseInt(hex.slice(1 + i * 2, 3 + i * 2), 16) / 255;
const linear = (c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const luminance = (hex) =>
  0.2126 * linear(channel(hex, 0)) +
  0.7152 * linear(channel(hex, 1)) +
  0.0722 * linear(channel(hex, 2));
const ratio = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

const TONES = ["slate", "brand", "blue", "green", "amber", "orange", "red", "violet"];
const SURFACES = ["background", "surface", "surface-2"];

let failures = 0;
function check(theme, label, fg, bg, minimum) {
  const value = ratio(fg, bg);
  const pass = value >= minimum;
  if (!pass) failures += 1;
  console.log(
    `${pass ? "ok  " : "FAIL"} ${theme.padEnd(5)} ${label.padEnd(44)} ${value.toFixed(2)} (min ${minimum})`,
  );
}

for (const [name, v] of Object.entries(themes)) {
  for (const surface of SURFACES) {
    check(name, `foreground on ${surface}`, v.foreground, v[surface], 4.5);
    check(name, `muted on ${surface}`, v.muted, v[surface], 4.5);
    check(name, `primary (links, icons) on ${surface}`, v.primary, v[surface], 4.5);
    check(name, `input-border on ${surface}`, v["input-border"], v[surface], 3);
  }
  check(name, "primary-foreground on primary (button)", v["primary-foreground"], v.primary, 4.5);
  check(
    name,
    "primary-foreground on primary-hover",
    v["primary-foreground"],
    v["primary-hover"],
    4.5,
  );
  check(name, "ring on background", v.ring, v.background, 3);
  check(name, "ring on surface", v.ring, v.surface, 3);
  for (const tone of TONES) {
    check(name, `tone-${tone}: fg on bg (badge)`, v[`tone-${tone}-fg`], v[`tone-${tone}-bg`], 4.5);
    check(name, `tone-${tone}: fg on surface (inline text)`, v[`tone-${tone}-fg`], v.surface, 4.5);
    check(name, `tone-${tone}: border on surface`, v[`tone-${tone}-border`], v.surface, 1.4);
  }
}

console.log(
  failures === 0 ? "\nAll contrast checks passed." : `\n${failures} contrast check(s) failed.`,
);
process.exit(failures === 0 ? 0 : 1);
