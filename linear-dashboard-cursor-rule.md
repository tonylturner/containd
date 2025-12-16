# UI / Frontend Design Rule – Linear-Style Analytics Dashboard

> **Purpose**: This codebase implements a modern analytics/dashboard-style web app.  
> When editing frontend or UI-related code, always follow the rules below so the design stays consistent.

---

## 1. Design Inspiration & Principles

- **Primary visual inspiration**: Linear and similar modern SaaS dashboards.
- **Core principles**:
  - Clean, minimal, high-contrast UI
  - Strong visual hierarchy (clear primary vs secondary actions)
  - Interactive data visualizations (charts, heatmaps, trends)
  - Proper loading states (skeletons/spinners/placeholders)
  - Smooth, subtle animations (no flashy transitions)
  - Mobile-responsive layout (desktop first, but must work well on tablet & mobile)
  - Accessibility-first: target **WCAG AA** contrast and keyboard navigation.

---

## 2. Color System (MUST KEEP EXACT HEX CODES)

**CRITICAL**: Always use these exact colors. Do **not** introduce new brand colors without explicit decision.

### Primary Colors (Blues)
- Primary Blue: `#2563EB` – primary actions/buttons
- Primary Blue Light: `#3B82F6` – hover states
- Primary Blue Dark: `#1E40AF` – pressed/active states
- Subtle Blue: `#DBEAFE` – light backgrounds/highlights

### Neutral Colors (Grays/Blacks)
- Background Dark: `#121212` – main dark background
- Surface Dark: `#1E1E1E` – cards/surfaces in dark mode
- Border Dark: `#2E2E2E` – separators/dividers
- Text Primary Dark: `#FFFFFF`
- Text Secondary Dark: `#A3A3A3`

### Light Mode Colors
- Background Light: `#F8FAFC`
- Surface Light: `#FFFFFF`
- Border Light: `#E2E8F0`
- Text Primary Light: `#0F172A`
- Text Secondary Light: `#64748B`

### Accent / Visualization Colors
- Success Green: `#10B981`
- Warning Yellow: `#FBBF24`
- Error Red: `#EF4444`
- Purple: `#8B5CF6`
- Teal: `#06B6D4`
- Pink: `#EC4899`
- Orange: `#F97316`

### Data Visualization Specific
- Chart Gradient Start: `#3B82F6` (blue)
- Chart Gradient End: `#8B5CF6` (purple)
- Data Series 1: `#2563EB`
- Data Series 2: `#8B5CF6`
- Data Series 3: `#06B6D4`
- Data Series 4: `#EC4899`
- Data Series 5: `#F97316`

### Status Indicators
- Low Activity: `#6B7280`
- Medium Activity: `#60A5FA`
- High Activity: `#2563EB`
- Very High Activity: `#1E40AF`

### Specific UI Elements
- Card Background: `#1E1E1E`
- Navigation Active: `#2563EB`
- Navigation Inactive: `#4B5563`
- Input Background: `#262626`
- Input Border Focus: `#3B82F6`
- Hover Overlay: `rgba(255, 255, 255, 0.05)`
- Shadow Color: `rgba(0, 0, 0, 0.5)`

---

## 3. Color Implementation Rules

When writing CSS/Tailwind or theming:

- **Use CSS variables** for all colors (e.g. `--color-primary`, `--color-bg`, etc.).
- **Use HSL values** in the CSS variables wherever possible (easier to adjust lightness/saturation).
- Support **both dark and light modes**:
  - Dark mode default for “pro” / dashboard feel.
  - Light mode must still be polished and consistent.
- Maintain at least **4.5:1 contrast ratio** for text vs background.
- Do **not** hardcode hex colors directly inside components; reference CSS vars or Tailwind theme tokens.

---

## 4. Tech Stack & Libraries (Preserve These)

When adding or modifying code:

- **Frontend Framework**: Next.js 15 (App Router) with **TypeScript**.
- **Styling**: Tailwind CSS v3 (with project-specific config using the palette above).
- **Component Library**: [Shadcn/ui](https://ui.shadcn.com/) for base UI components:
  - Buttons, Cards, Badges, Avatars
  - Dropdown Menu, Select, Tabs, Table, Progress, etc.
- **State Management**:
  - Prefer React hooks and local state.
  - Use React context for global app state (auth, theme, etc.), not third-party state libs unless explicitly chosen.

Backend stack (for context only, not app-specific):

- Typical setup assumed: Go + Gin + PostgreSQL or SQLite, RESTful API that feeds the dashboard.
- Frontend expects JSON APIs with predictable, typed responses.

---

## 5. Layout & Component Patterns

When building new screens, **treat everything as part of a modern analytics dashboard**:

- **Header / Navigation**
  - Top-level header with app name/logo, main nav, and user avatar dropdown.
  - Clear active nav state using `#2563EB`.
- **Dashboard Layout**
  - Above-the-fold: concise KPIs and primary charts.
  - Use **cards** for grouping content: consistent padding, rounded corners, subtle shadows.
- **Common Component Types**
  - **KPI Cards**  
    - Small cards with title, main value, trend (up/down), period.
    - May include mini-sparkline or subtle icon.
  - **Activity / Intensity Visualizations**  
    - Grids, heatmaps, or charts that show activity over time.
    - Use the defined series colors and gradients.
  - **Leaderboards / Rank Lists**  
    - Tables or lists with items sorted by score/value.
    - Use badges for rankings (e.g., 1st/2nd/3rd).
  - **Quick Actions**  
    - A small grid of primary actions (2–6 items), using buttons or cards.
- Always apply **proper spacing and alignment**:
  - Use consistent gaps (`gap-4`, `gap-6`) and padding (`p-4`, `p-6`) across cards and layouts.
  - Avoid cramming too many components in a single row.

---

## 6. Interaction, Loading & Accessibility

- **Loading States**
  - Use skeleton loaders for cards, charts, and tables.
  - Avoid layout shifts: reserve space while data loads.
- **Animations**
  - Use subtle transitions (`transition-all`, `duration-150`–`300`).
  - No aggressive or distracting animations. Think **Linear-level subtlety**.
- **Responsive Design**
  - Layout should gracefully stack on smaller screens.
  - Important KPIs and charts remain visible and legible on mobile.
- **Accessibility**
  - All interactive elements must be keyboard-accessible (tab, enter/space).
  - Provide ARIA labels where necessary (icons, charts, custom controls).
  - Ensure focus styles are visible and consistent (use primary or subtle blue outlines).

---

## 7. Code Style & Structure

- **TypeScript**
  - Use strict mode and typed props/interfaces.
  - Avoid `any` whenever possible.
- **React Components**
  - Use functional components and hooks.
  - Prefer small, composable components over huge monoliths.
- **File / Naming Conventions**
  - Components: `PascalCase` filenames and component names.
  - Folders and non-component files: `kebab-case`.
- **Styling**
  - Use Tailwind utility classes as the primary styling approach.
  - For complex styles or theme logic, move them into CSS modules or global CSS with variables.

---

## 8. Data & API Integration (Generic)

When consuming backend data:

- Assume **RESTful JSON APIs** returning typed objects.
- Always:
  - Validate data shape where it enters the component tree.
  - Handle errors gracefully with clear, non-technical user messages.
  - Provide empty states (no data) and error states (failed fetch) with helpful guidance.

Real-time or periodic updates can be done via polling or WebSockets, but must not break layout or overload the UI.

---

## 9. General “Do / Don’t”

**Do:**
- Aim for the polish and minimalism of **Linear**.
- Use the defined **color palette** and **component patterns**.
- Keep designs clean, breathable, and easy to scan.
- Maintain high contrast and accessibility.

**Don’t:**
- Introduce random new colors or visual styles.
- Hardcode colors directly into components (use theme tokens/vars).
- Add heavy, flashy animations or noisy gradients.
- Break existing layout consistency for one-off pages.

---

Use this rule as the **single source of truth** for UI/UX, theming, and frontend structure. Any new views or components should feel like they naturally belong in the same product experience described here.
