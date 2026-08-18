# NetFlow ISP Reseller Billing V20 — Supabase + Cross-Device Edition

This folder is the GitHub Pages-ready website.

## What V20 fixes
- Shared Supabase workspace: laptop and phone see the same company/customer/package/billing data.
- Local data is migrated/merged into the cloud workspace when you first connect.
- Cross-device updates use Supabase Realtime plus a 5-second fallback refresh.
- Add/Edit/Delete company, customer, package, invoice, payment and expense data persists to Supabase.
- Excel/CSV import now also saves to Supabase.
- Responsive desktop + mobile layout.
- Staff roles/permissions remain supported.
- No ZalPro or MikroTik live connection is required.

## Supabase setup
1. In Supabase SQL Editor, run `supabase_setup.sql`.
2. If you already ran the previous SQL successfully, run the V20 Realtime block at the bottom too.
3. In the website open **Settings**.
4. Enter:
   - Supabase Project URL: `https://YOUR_PROJECT.supabase.co`
   - Supabase **anon/public** key (never service-role).
5. Click **Save Cloud Settings**.
6. Enter your Supabase Auth email/password and click **Login**.
7. After login, the Settings page should show **Cloud connected** and a workspace ID.

## GitHub Pages
Upload the contents of this `v20` folder to your GitHub repository (or upload the ZIP contents). Make sure `index.html` is at the published site root.

## Important
The website does not contain a service-role key. The anon/public key is intended for browser use with Supabase RLS enabled.
