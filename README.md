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
4. This build already has your Supabase Project URL and **publishable key** configured, so you do not need to paste them again.
5. On each device (laptop and phone), open **Settings** and log in with the same Supabase Auth account. Supabase keeps the login session on that device.
6. Enter your Supabase Auth email/password and click **Login**.
7. After login, the Settings page should show **Cloud connected** and a workspace ID.

## GitHub Pages
Upload the contents of this `v20` folder to your GitHub repository (or upload the ZIP contents). Make sure `index.html` is at the published site root.

## Important
The website contains only the Supabase **publishable** key, which is intended for browser use. The secret/service-role key is NOT included. Database security is provided by the RLS policies in `supabase_setup.sql`.

### Important for phone + laptop
The data is shared through Supabase, but the user must be logged in on each device. After logging in on both devices, a company/customer added on one device will appear on the other through Realtime (with a 5-second fallback refresh).
