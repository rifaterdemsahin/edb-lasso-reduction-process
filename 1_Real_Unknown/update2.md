The update is mostly correct, but there is one important issue still remaining.

✅ Good changes found
Added import shutil ✔️
Added redact_nested_tar_bz2() ✔️
Added recursive .tar.bz2 processing in redact_directory() ✔️
Added .tar.bz2 support in main() ✔️
Added dynamic output mode (w:gz / w:bz2) ✔️

All visible in lasso_reduction.py.

❌ Remaining bug

Your redact_file() is still:

try:
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
except Exception as e:
    print(f"[!] Warning: Could not read {file_path}: {e}")
    return 0


This means binary files that fail to read are simply skipped and not copied to output.

Replace it with:

try:
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    redacted_content, matches = self.redact_text(
        content,
        source_identifier=file_path.name
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(redacted_content)

    return len(matches)

except Exception:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(file_path, output_path)
    return 0


This preserves binaries, certificates, images, dumps, etc.

Next test

Run:

python .\lasso_reduction.py -i .\input\lassoreport.tar.gz -o .\output\lassoreport_redacted.tar.gz


You should now see lines like:

[*] Processing nested archive:


for each of the 9 node bundles. This will confirm the nested .tar.bz2 files are actually being opened and inspected.

Validation

After running:

Select-String -Path .\output\lasso_reduction_manifest.json -Pattern "total_redactions"


If it still shows:

"total_redactions": 0


then the diagnostic logs simply don't contain anything matching your current regex rules, and the next step would be enhancing the detection patterns rather than archive handling.
