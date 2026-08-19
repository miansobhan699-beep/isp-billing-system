# NetFlow ISP Reseller Billing V21 — Supabase + Cross-Device Edition

This folder is the GitHub Pages-ready website.

## What V21 fixes
- Shared Supabase workspace: laptop and phone see the same company/customer/package/billing data.
- Fixed recursive RLS policy checks that can cause Supabase profile/workspace requests to fail.
- Added a Settings → Test Cloud Connection check with clearer iPhone/Safari network errors.
- Local data is migrated/merged into the cloud workspace when you first connect.
- Cross-device updates use Supabase Realtime plus a 5-second fallback refresh.
- Add/Edit/Delete company, customer, package, invoice, payment and expense data persists to Supabase.
- Excel/CSV import now also saves to Supabase.
- Responsive desktop + mobile layout.
- Staff roles/permissions remain supported.
- No ZalPro or MikroTik live connection is required.

## Supabase setup
1. In Supabase SQL Editor, run `supabase_setup.sql`.
2. If you already ran the previous SQL successfully, run the V21 Realtime block at the bottom too.
3. In the website open **Settings**.
4. Enter:
   - Supabase Project URL: `https://YOUR_PROJECT.supabase.co`
   - Supabase **anon/public** key (never service-role).
5. Click **Save Cloud Settings**.
6. Enter your Supabase Auth email/password and click **Login**.
7. After login, the Settings page should show **Cloud connected** and a workspace ID.

## GitHub Pages
Upload the contents of this `V21` folder to your GitHub repository (or upload the ZIP contents). Make sure `index.html` is at the published site root.

## Important
The website does not contain a service-role key. The anon/public key is intended for browser use with Supabase RLS enabled.


## Important V21 fix
If the old SQL was already run, **run the complete `supabase_setup.sql` again**. The V21 SQL replaces the old recursive `isp_profiles` policy checks with SECURITY DEFINER helper functions. This is important for login/signup and workspace loading.

After running SQL:
1. Refresh the GitHub Pages site.
2. Open **Settings**.
3. Verify the Project URL and publishable/anon public key.
4. Tap **Test Cloud Connection**.
5. Then create/login to the account.

The browser may safely contain a Supabase publishable key (`sb_publishable_...`) or legacy anon key. Never put a `service_role` or `sb_secret_...` key in the website.
