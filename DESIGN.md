# DESIGN.md — QuantumTrust Visual Design Specification

QuantumTrust is a forensic-grade PDF digital-signature verification instrument. The interface must feel like precision laboratory equipment, not a "security startup" landing page. Every design decision serves information density and trust signaling, not decoration.

---

## Philosophy

- **Restraint is the aesthetic.** Visual noise undermines confidence in a verification tool.
- **Status is king.** Verdict (AUTHENTIC / TAMPERED / SUSPICIOUS), threat score, and signature status must always be the most prominent visual element on screen.
- **Monospace for data.** All cryptographic values — hashes, algorithm names, certificate fields, key sizes, byte ranges — use a monospace typeface.
- **Semantic color only.** No rainbow. Color carries meaning: blue = system/accent, green = authentic/valid, amber = suspicious/warning, red = tampered/critical/danger.
- **Motion answers actions.** Animations only on meaningful state changes: upload progress steps, verdict reveal, status transitions. No scroll animations, no hover sparkles, no ambient motion.

---

## Color System (Monochrome / Black & White)

All colors are defined as CSS custom properties on `:root`.

### Base Surfaces

| Token | Hex | Usage |
|---|---|---|
| `--bg-base` | `#000000` | True OLED black background |
| `--bg-surface` | `#0C0C0C` | Card, panel, sidebar background |
| `--bg-raised` | `#151515` | Elevated element, metric containers |
| `--bg-hover` | `#1F1F1F` | Hover state for interactive elements |
| `--bg-active` | `#2A2A2A` | Active/selected state |

### Borders

| Token | Hex | Usage |
|---|---|---|
| `--border` | `#262626` | Card borders, panel dividers |
| `--border-subtle` | `#181818` | Very subtle dividers |
| `--border-accent` | `#FFFFFF` | Stark white contrast border |

### Text

| Token | Hex | Usage |
|---|---|---|
| `--text-primary` | `#FFFFFF` | Primary readable text |
| `--text-secondary` | `#A3A3A3` | Secondary / meta text, labels |
| `--text-muted` | `#666666` | De-emphasized, placeholder |
| `--text-code` | `#E5E5E5` | Monospace / code values |
| `--text-accent` | `#FFFFFF` | Accent text, links |

### Accent

| Token | Hex | Usage |
|---|---|---|
| `--accent` | `#FFFFFF` | Primary accent — crisp white |
| `--accent-dim` | `#181818` | Dim accent for backgrounds |
| `--accent-glow` | `rgba(255, 255, 255, 0.08)` | Subtle white contrast glow |

### Semantic States (High Contrast B&W)

| Token | Hex | Usage |
|---|---|---|
| `--ok` | `#FFFFFF` | Authentic / valid state |
| `--ok-dim` | `#111111` | Authentic card background |
| `--ok-border` | `#3A3A3A` | Authentic border |
| `--warn` | `#CCCCCC` | Suspicious / warning state |
| `--warn-dim` | `#141414` | Warning card background |
| `--warn-border` | `#4E4E4E` | Warning border |
| `--danger` | `#FFFFFF` (Inverted) | Tampered / critical danger (Solid white block with black text) |
| `--danger-dim` | `#181818` | Danger background |
| `--danger-border` | `#6B6B6B` | Danger border |
| `--neutral` | `#888888` | Neutral / unknown state |
| `--ok` | `#22C55E` | AUTHENTIC, valid signature, verified integrity |
| `--ok-dim` | `#0F3A1E` | Authentic state background |
| `--ok-border` | `#166534` | Authentic state border |
| `--warn` | `#F59E0B` | SUSPICIOUS, warning, cert issues |
| `--warn-dim` | `#3A2800` | Suspicious state background |
| `--warn-border` | `#78450A` | Suspicious state border |
| `--danger` | `#EF4444` | TAMPERED, critical, invalid signature |
| `--danger-dim` | `#3A0A0A` | Tampered state background |
| `--danger-border` | `#7C1919` | Tampered state border |
| `--neutral` | `#4A5A78` | Unknown, unavailable, neutral |
| `--neutral-dim` | `#1A1F2E` | Neutral state background |

---

## Typography

### Typefaces

Import from Google Fonts:

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
```

| Role | Family | Weight |
|---|---|---|
| **Display / Headings** | `IBM Plex Mono` | 600 |
| **UI Labels / Navigation** | `IBM Plex Mono` | 500 |
| **Body text** | `Inter` | 400 |
| **Strong body** | `Inter` | 600 |
| **Cryptographic values** | `IBM Plex Mono` | 400 |
| **Status badges** | `IBM Plex Mono` | 600 |

### Type Scale

```
--text-xs:   0.6875rem  (11px)  — metadata, timestamps
--text-sm:   0.8125rem  (13px)  — labels, badges, secondary
--text-base: 0.9375rem  (15px)  — body, table rows
--text-md:   1.0625rem  (17px)  — card titles, section heads
--text-lg:   1.25rem    (20px)  — page subtitle
--text-xl:   1.5rem     (24px)  — section heading
--text-2xl:  2rem       (32px)  — major metric (threat score)
--text-3xl:  2.75rem    (44px)  — verdict (AUTHENTIC/TAMPERED)
--text-hero: 3.5rem     (56px)  — landing page headline
```

### Line Height

- Body: `1.6`
- Headings: `1.2`
- Code/mono: `1.5`
- Labels: `1.0`

---

## Spacing

8px grid system.

```
--space-1:   4px
--space-2:   8px
--space-3:   12px
--space-4:   16px
--space-5:   20px
--space-6:   24px
--space-8:   32px
--space-10:  40px
--space-12:  48px
--space-16:  64px
--space-20:  80px
```

---

## Layout

### Structure

```
+--[Sidebar: 240px fixed]--+--[Content area: fills remaining]--+
|                          |                                    |
|  QuantumTrust Logo       |  Page Header                       |
|                          |  ─────────────────────────────     |
|  [nav links]             |  Content Grid                      |
|                          |                                    |
|  ─────────────────       |                                    |
|  System status           |                                    |
+──────────────────────────+────────────────────────────────────+
```

- Sidebar: `240px` wide, fixed position, full viewport height
- Content: `margin-left: 240px`, scrollable
- Content max-width: `1280px` (centered within content area on very wide screens)
- Content padding: `32px` horizontal, `32px` top

### Responsive Breakpoints

```
--bp-sm:   640px   — mobile/small
--bp-md:   768px   — tablet
--bp-lg:   1024px  — laptop
--bp-xl:   1280px  — desktop
--bp-2xl:  1536px  — wide
```

Mobile: sidebar collapses to top horizontal bar or hamburger.
Tablet: sidebar collapses, icon-only or off-canvas.

---

## Cards

```css
.card {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: var(--space-6);
}
```

- Border radius: `4px` — precise, not soft
- No box-shadow on standard cards (the dark background provides natural depth)
- Use `--border-accent` border for highlighted/active cards

### Card Variants

- `.card--ok` — `--ok-dim` background, `--ok-border` border
- `.card--warn` — `--warn-dim` background, `--warn-border` border
- `.card--danger` — `--danger-dim` background, `--danger-border` border
- `.card--neutral` — `--neutral-dim` background

---

## Status Badges

```css
.badge {
  font-family: 'IBM Plex Mono', monospace;
  font-size: var(--text-xs);
  font-weight: 600;
  letter-spacing: 0.08em;
  padding: 3px 8px;
  border-radius: 2px;
  text-transform: uppercase;
}
```

Variants:
- `.badge--ok`: `--ok` text, `--ok-dim` bg, `--ok-border` border
- `.badge--warn`: `--warn` text, `--warn-dim` bg, `--warn-border` border
- `.badge--danger`: `--danger` text, `--danger-dim` bg, `--danger-border` border
- `.badge--neutral`: `--neutral` text, `--neutral-dim` bg

---

## Verdict Display

The final verdict (AUTHENTIC / TAMPERED / SUSPICIOUS) is the primary visual centerpiece on the security and verification pages.

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│                  AUTHENTIC                          │
│              Final Verdict                          │
│                                                     │
└─────────────────────────────────────────────────────┘
```

- Font: `IBM Plex Mono`, 600 weight, `--text-3xl`
- AUTHENTIC: `--ok` color, `--ok-dim` background, `--ok-border` border
- TAMPERED: `--danger` color, `--danger-dim` background, `--danger-border` border
- SUSPICIOUS: `--warn` color, `--warn-dim` background, `--warn-border` border

---

## Buttons

### Primary

```css
.btn-primary {
  background: var(--accent);
  color: #fff;
  font-family: 'IBM Plex Mono', monospace;
  font-size: var(--text-sm);
  font-weight: 500;
  padding: 10px 20px;
  border-radius: 3px;
  border: none;
}
.btn-primary:hover { background: #4A8EE8; }
```

### Secondary

```css
.btn-secondary {
  background: transparent;
  color: var(--text-secondary);
  border: 1px solid var(--border);
  font-family: 'IBM Plex Mono', monospace;
  font-size: var(--text-sm);
  padding: 10px 20px;
  border-radius: 3px;
}
.btn-secondary:hover { border-color: var(--accent); color: var(--text-accent); }
```

### Danger

```css
.btn-danger {
  background: var(--danger-dim);
  color: var(--danger);
  border: 1px solid var(--danger-border);
}
```

---

## Data Tables

```css
.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--text-sm);
}
.data-table th {
  font-family: 'IBM Plex Mono', monospace;
  font-size: var(--text-xs);
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  font-weight: 500;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  text-align: left;
}
.data-table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border-subtle);
  color: var(--text-primary);
  font-family: 'Inter', sans-serif;
}
.data-table tr:hover td { background: var(--bg-hover); }
```

Numeric columns: right-aligned, `IBM Plex Mono`.
Hash/fingerprint values: `IBM Plex Mono`, `--text-code` color, truncated with tooltip.

---

## Upload Zone

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│         ↑  Upload Signed PDF                        │
│                                                     │
│     Drag & drop your PDF here, or click to browse   │
│                                                     │
│         PDF only · Max 50MB · Secure analysis       │
│                                                     │
└─────────────────────────────────────────────────────┘
```

- Border: `2px dashed var(--border)`
- Border radius: `4px`
- On hover/drag-over: `border-color: var(--accent)`, `background: var(--accent-glow)`
- Transition: `border-color 0.2s, background 0.2s`

---

## Progress Steps

```
● Parsing PDF...             ← active (spinning dot)
✓ Detecting signature        ← complete (check)
○ Verifying certificate      ← pending (empty dot)
```

- Active step: `--accent` color, animated indicator
- Completed step: `--ok` color, checkmark
- Pending step: `--text-muted` color

---

## Navigation Sidebar

```
┌──────────────────────┐
│  QuantumTrust        │  ← IBM Plex Mono 600, --text-primary
│  Signature Security  │  ← IBM Plex Mono 400, --text-muted, text-xs
├──────────────────────┤
│  ○ Dashboard         │  ← active: --accent, bg: --bg-active
│  ○ Verify Document   │
│  ○ Security Analysis │
├──────────────────────┤
│  ─────────────────── │
│  System              │  ← section label, --text-muted, text-xs
│  ○ Analysis History  │
└──────────────────────┘
```

- Nav item: `Inter` 500, `--text-secondary`, padding `10px 16px`
- Active nav item: `--text-primary`, left border `3px solid var(--accent)`, `--bg-active`
- Hover: `--bg-hover`, `--text-primary`

---

## Threat Score

Visual: horizontal score bar or compact numerical display.

```
Threat Score

82 / 100
████████████████░░░  CRITICAL
```

- Bar: gradient from `--ok` (0) through `--warn` (50) to `--danger` (100)
- Score number: `IBM Plex Mono`, `--text-2xl`, 600 weight
- Level badge: `.badge--danger` for CRITICAL, `.badge--warn` for HIGH/MEDIUM, `.badge--ok` for LOW

---

## Quantum Metrics

Four metrics displayed in a 2×2 grid of compact stat panels:

```
┌──────────────────┬──────────────────┐
│  State Similarity│  Correlation     │
│  0.94            │  0.87            │
├──────────────────┼──────────────────┤
│  Disturbance     │  Anomaly Distance│
│  0.12            │  0.08            │
└──────────────────┴──────────────────┘
```

Label: `IBM Plex Mono`, `--text-xs`, `--text-muted`
Value: `IBM Plex Mono`, `--text-2xl`, 600, `--text-primary`

---

## Responsive Rules

- Tables: horizontal scroll on mobile, key columns pinned
- Cards: 1-column stack on mobile, 2-column on tablet, N-column on desktop
- Navigation: fixed sidebar on desktop (≥1024px), top bar on tablet, off-canvas on mobile
- Upload zone: full-width on all breakpoints
- Verdict text: scale down to `--text-xl` on mobile

---

## Accessibility

- All interactive elements keyboard-navigable
- Focus rings: `outline: 2px solid var(--accent)`, `outline-offset: 2px`
- Color is never the only differentiator — always paired with text/icon
- Sufficient contrast: all primary text against all background surfaces passes WCAG AA
- Reduced motion: `@media (prefers-reduced-motion: reduce)` disables all transitions/animations
- `aria-live` regions for status updates during upload/analysis
- Meaningful button text — no "Click here" or icon-only buttons without labels

---

## Anti-Patterns (Do Not Use)

- ❌ Large decorative AI/brain/quantum graphics
- ❌ Excessive glassmorphism (frosted glass overlays)
- ❌ Neon glow effects
- ❌ Rainbow gradients
- ❌ Generic "SaaS card kit" look (identical rounded cards, soft grey shadows)
- ❌ Fabricated page numbers or object IDs without cryptographic/structural evidence

---

## Tampering Localization Specification

The Tampering Localization Engine presents deterministic, evidence-based structural locations where unauthorized modifications occurred:

```
┌────────────────────────────────────────────────────────────┐
│ TAMPERING LOCALIZATION                                     │
├────────────────────────────────────────────────────────────┤
│ STATUS: LOCALIZED   LEVEL: PAGE_LEVEL   CONFIDENCE: HIGH   │
│                                                            │
│ • Narrative Summary Callout                                │
│ • Affected Items List:                                     │
│   ┌──────────────────────────────────────────────────────┐ │
│   │ #1 Page 3 (Object 14)       CONTENT_CHANGED          │ │
│   │ Path: /Pages/Page[3]/Object[14]                      │ │
│   │ Before: [Signed baseline state]                      │ │
│   │ After:  [Modified current state]                     │ │
│   │ Evidence: ByteRange digest mismatch in revision 1    │ │
│   └──────────────────────────────────────────────────────┘ │
│ • Format Limitation & Baseline Disclosures                 │
└────────────────────────────────────────────────────────────┘
```

- **Visual Tone:** Professional, evidence-driven, clear distinctions between authentic signed revisions, legitimate incremental updates, and unauthorized content modifications.
- **Before/After Diffing:** High-contrast, clean red/blue tonal contrast for trusted baseline vs current document states.

- ❌ ALL CAPS section eyebrows (e.g., "SECURITY DASHBOARD" above every heading)
- ❌ Middle-dot meta strings (A · B · C)
- ❌ Arrow appended to every link ("Verify →")
- ❌ Animated backgrounds, particle effects, or SVG noise textures
- ❌ Multiple border-radius sizes (pick one: 4px, used consistently)
