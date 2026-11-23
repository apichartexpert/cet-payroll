# CET Payroll

Monthly payroll workspace for Constant Energy Services (Thailand) Co., Ltd., built as a single HTML page (`index.html`).

- GitHub Pages: https://apichartexpert.github.io/cet-payroll/
- claude.ai artifact: https://claude.ai/artifact/LYkBmnXEY16zjVddAvfqFF

- Shared, multi-user: the Render deployment (see below), with its own login.

On GitHub Pages and claude.ai each browser keeps its own data. On Render everyone who logs in works on one shared data set. On first use, enter the company tax ID, payroll bank account and SSO account under **ตั้งค่า**.

## Shared version on Render

`server/` is a small FastAPI app that serves the same `index.html` and keeps one shared payroll data set:

- **Login** with usernames and passwords managed by an admin under **ตั้งค่า → ผู้ใช้งาน**. Roles: ผู้ดูแลระบบ (admin), ผู้แก้ไข (editor), ดูอย่างเดียว (viewer).
- **Encrypted at rest** with AES-256-GCM; the key comes from `DATA_KEY`.
- **No silent overwrites:** every save names the version it started from. If someone else saved in between, the app asks whether to load their version or save over it. Open screens refresh when others save.
- **History:** every save and user change is logged (who, when, version) under **ตั้งค่า**.

Deploy:

1. Create a free Postgres database on [Neon](https://neon.tech) and copy its connection string.
2. Render → **New + → Blueprint** → choose this repository (`render.yaml`).
3. Fill in `DATABASE_URL` (the Neon string), `ADMIN_USERNAME` and `ADMIN_PASSWORD`. Render generates `DATA_KEY`; keep it, because without it the saved data cannot be read.
4. Open the Render URL, log in as the admin, import the data file or payroll register, then add users under **ตั้งค่า**.

Forgot the admin password: in Render → Environment set `ADMIN_USERNAME`, a new `ADMIN_PASSWORD` (at least 10 characters) and `ADMIN_RESET` = `1`, save (Render restarts the service), log in, then delete `ADMIN_RESET` and `ADMIN_PASSWORD`.

Run the tests with `python -m pytest server/tests`.

## Monthly flow

1. **Import** – drop files on the import page (นำเข้าข้อมูล): the MPA, supporting documents, the payroll register workbook. Password-protected Excel files open in the browser after you type the password; the file and password never leave the browser.
2. **Review** – every MPA line is shown with the change it will make (new hire, resignation, proration, OT, unpaid leave, recurring allowance).
3. **Generate** – this month = previous month's payroll + this month's MPA.
4. **Check and close** – compare each person's net pay with the previous month, then close the period.
5. **Export** – payroll register in the CET layout (`MMMYYYY` + `Tax calculationNN`), PND1 attachment (.xlsx / .txt), SSO 1-10 (.xlsx / .txt), BBL salary file (.txt), PEAK journal (.xlsx).
6. **Bonus runs** – on the run page, **+ เพิ่มงวดโบนัส** creates a bonus run for the month: type each person's bonus and the withholding tax is worked out as the extra annual tax the bonus causes (it can be set by hand), then close the run. Alternatively, a bonus register (file or sheet name containing "Bonus", or a register with bonus but no salary) is saved as an extra pay run in its month and never replaces the salary run. Each bonus run has its own pay date and exports: bonus register, PND1 (.xlsx / .txt) and BBL file (`CET YYYYMM Bonus.txt`). Months already covered by imported actuals include the bonus there, so it is not counted twice in tax; for later months the bonus and its withholding go into the year-to-date tax.

## Calculation rules

- Withholding tax: a regular level amount each month, plus the marginal tax on one-off income in the month it is paid; December (or the last month of employment) withholds the balance of the annual tax.
- Provident fund: salary × rate, rounded up to the whole baht.
- Social security: 5% of wages actually paid, wage ceiling 17,500 (875 a month).
- First and last months are prorated by calendar days.

## Data

No payroll data is stored in this repository. The app keeps its data in the browser (localStorage) of the person using it; use **ตั้งค่า → สำรองข้อมูลทั้งหมด** for a backup file. Do not commit payroll registers, MPAs, backups or exports – `.gitignore` blocks the common file types.

## Libraries

Loaded from CDNs at runtime: [xlsx-js-style 1.2.0](https://github.com/gitbrent/xlsx-js-style) (SheetJS 0.18.5 with cell styles) and the IBM Plex Sans Thai font from Google Fonts.
