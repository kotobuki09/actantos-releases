# ActantOS Operator Design System

## 1. Atmosphere & Identity

ActantOS operator surfaces feel like a quiet command console: dense enough for incident work, restrained enough to keep policy review readable. The signature is cool, layered depth with muted blue accents and thin structural borders instead of decorative cards or splashy gradients.

## 2. Color

### Palette

| Role | Token | Dark | Usage |
|------|-------|------|-------|
| Surface/primary | `--bg` | `#0b1017` | App background |
| Surface/secondary | `--panel` | `#131b27` | Primary panels |
| Surface/elevated | `--panel-alt` | `#0f1520` | Inputs, buttons, inset panels |
| Border/default | `--border` | `#243244` | Tables, controls, separations |
| Text/primary | `--text` | `#ebf1fa` | Headings and body |
| Text/secondary | `--muted` | `#9eacc0` | Metadata and helper copy |
| Accent/primary | `--accent` | `#7fb3ff` | Focus states, active tabs, system highlights |
| Status/success | `--good` | `#3ddc97` | Allow, healthy state |
| Status/warning | `--warn` | `#ffd166` | Approval-required, cautions |
| Status/error | `--danger` | `#ff8b8b` | Deny, destructive state |

### Rules

- Use the blue accent only for active selection, focus, and route-level emphasis.
- Surface separation comes from tonal shift plus border lines, not shadows.
- New operator pages should reuse these tokens before introducing any new hue.

## 3. Typography

### Scale

| Level | Size | Weight | Line Height | Usage |
|-------|------|--------|-------------|-------|
| H1 | `30px` | `700` | `1.2` | Page title |
| H2 | `18px` | `600` | `1.3` | Section title |
| Body | `14px` | `400` | `1.5` | Core operator copy |
| Meta | `13px` | `400` | `1.4` | Secondary details |
| Label | `12px` | `700` | `1.3` | Table headers, badges |

### Font Stack

- Primary: `Inter, "Segoe UI", system-ui, sans-serif`
- Mono: `ui-monospace, SFMono-Regular, Consolas, monospace`

### Rules

- Metadata and code previews stay compact at `13px`.
- Uppercase labels are reserved for structural cues, not body copy.

## 4. Spacing & Layout

### Base Unit

All spacing derives from `4px`.

| Token | Value | Usage |
|-------|-------|-------|
| `--space-1` | `4px` | Tight icon/text pairing |
| `--space-2` | `8px` | Inline groups |
| `--space-3` | `12px` | Compact panel internals |
| `--space-4` | `16px` | Default control spacing |
| `--space-5` | `20px` | Header and page rhythm |
| `--space-6` | `24px` | Panel padding |

### Grid

- Max content width: `1200px`
- Mobile breakpoint: `800px`
- Panels use single-column flow on mobile.

### Rules

- Use `8px` corner radius for panels and controls.
- Tables collapse to stacked blocks on mobile instead of horizontal overflow.

## 5. Components

### Operator Panel

- **Structure**: header block, explanatory copy, action or data region
- **Spacing**: `--space-5` outer rhythm, `--space-4` internal gaps
- **States**: default only
- **Accessibility**: semantic heading plus descriptive text
- **Motion**: none required

### Action Button

- **Structure**: text label in bordered inline-flex button
- **Variants**: default, success, danger
- **Spacing**: `8px 10px`
- **States**: default, hover, disabled
- **Accessibility**: keyboard focus must be visible through accent border treatment
- **Motion**: color/background transition only

### Status Badge

- **Structure**: inline badge with subtle border and semantic color
- **Variants**: active, allow, deny, approval_required
- **Spacing**: `3px 8px`
- **States**: default only
- **Accessibility**: never rely on color alone; text always names the state
- **Motion**: none

### Policy Source Preview

- **Structure**: monospace `<pre>` block inside a bordered inset panel
- **Variants**: active bundle, selected bundle
- **Spacing**: `14px` padding
- **States**: default only
- **Accessibility**: preserve text wrapping for long policy content
- **Motion**: none

## 6. Motion & Interaction

### Timing

| Type | Duration | Easing | Usage |
|------|----------|--------|-------|
| Micro | `150ms` | `ease-out` | Button hover, badge emphasis |
| Standard | `200ms` | `ease-in-out` | Async feedback state changes |

### Rules

- Operator pages should feel immediate; avoid decorative motion.
- Async actions update inline feedback instead of opening modals for this milestone.

## 7. Depth & Surface

### Strategy

`tonal-shift + borders`

- Panels use a darker-to-lighter vertical surface ramp.
- Inputs, buttons, and previews sit on `--panel-alt` with `--border`.
- Shadows are avoided; depth comes from tonal layering and spacing.
