# NetFlow ISP Reseller Billing V19 — Data Sync Fix

This version fixes the local dashboard/data issue:
- Local mode always has Owner/Admin permissions.
- Add Company / Add Customer / Add Package / Add Expense work without Supabase.
- Saved local data is rendered immediately on the dashboard.
- Dashboard shows live company/customer/package counts and company revenue/commission.
- Company and customer delete/edit actions remain enabled.
- Existing localStorage data is preserved.
- Supabase remains optional; it is only used when a valid workspace is connected.

Open `index.html` directly or host the folder with GitHub Pages.
