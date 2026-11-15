# CET Payroll

Monthly payroll workspace for Constant Energy Services (Thailand) Co., Ltd., built as a single HTML page (`index.html`).

- GitHub Pages: https://apichartexpert.github.io/cet-payroll/
- claude.ai artifact: https://claude.ai/artifact/LYkBmnXEY16zjVddAvfqFF

Each browser keeps its own data, so the two links do not share data: use **ตั้งค่า → สำรองข้อมูลทั้งหมด** and restore the backup to move between them. On first use, enter the company tax ID, payroll bank account and SSO account under **ตั้งค่า**.

## Monthly flow

1. **Import** – drop files on the import page (นำเข้าข้อมูล): the MPA, supporting documents, the payroll register workbook. Password-protected Excel files open in the browser after you type the password; the file and password never leave the browser.
2. **Review** – every MPA line is shown with the change it will make (new hire, resignation, proration, OT, unpaid leave, recurring allowance).
3. **Generate** – this month = previous month's payroll + this month's MPA.
4. **Check and close** – compare each person's net pay with the previous month, then close the period.
5. **Export** – payroll register in the CET layout (`MMMYYYY` + `Tax calculationNN`), PND1 attachment (.xlsx / .txt), SSO 1-10 (.xlsx / .txt), BBL salary file (.txt), PEAK journal (.xlsx).

## Calculation rules

- Withholding tax: a regular level amount each month, plus the marginal tax on one-off income in the month it is paid; December (or the last month of employment) withholds the balance of the annual tax.
- Provident fund: salary × rate, rounded up to the whole baht.
- Social security: 5% of wages actually paid, wage ceiling 17,500 (875 a month).
- First and last months are prorated by calendar days.

## Data

No payroll data is stored in this repository. The app keeps its data in the browser (localStorage) of the person using it; use **ตั้งค่า → สำรองข้อมูลทั้งหมด** for a backup file. Do not commit payroll registers, MPAs, backups or exports – `.gitignore` blocks the common file types.

## Libraries

Loaded from CDNs at runtime: [xlsx-js-style 1.2.0](https://github.com/gitbrent/xlsx-js-style) (SheetJS 0.18.5 with cell styles) and the IBM Plex Sans Thai font from Google Fonts.
