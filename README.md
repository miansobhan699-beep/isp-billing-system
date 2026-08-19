NetFlow ISP Billing - Invoice & Customer Status Fix

Fixes:
- Invoice creation now validates customer, saves a complete invoice, refreshes the invoice count, and opens a printable bill automatically.
- Billing page shows total, paid, unpaid and partial invoice counts.
- Added Print Bill action to every invoice.
- Customer page now has separate All, Paid, Unpaid, Partial and No Invoice filters plus status cards.
- Customer rows show paid amount, due amount and billing status.
- Monthly bill generation reports the actual number created.
- Supabase/SQL was not changed.
