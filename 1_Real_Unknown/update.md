The full file is too large to reliably recreate line-for-line from the excerpt alone, and I don't want to invent parts of lasso_reduction.py.

The quickest way to get a correct full updated file is to apply the changes directly to your existing file.

Create a backup:

Copy-Item .\lasso_reduction.py .\lasso_reduction.py.bak


Then edit:

notepad .\lasso_reduction.py


Apply these four changes to lasso_reduction.py:

Add:
import shutil

Add the new method:
def redact_nested_tar_bz2(self, archive_path: Path, output_path: Path):
    """Extract, redact and rebuild nested .tar.bz2 archives."""

    import tempfile

    with tempfile.TemporaryDirectory() as tmp_in, tempfile.TemporaryDirectory() as tmp_out:

        with tarfile.open(archive_path, "r:bz2") as tar:
            tar.extractall(tmp_in)

        self.redact_directory(
            Path(tmp_in),
            Path(tmp_out)
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with tarfile.open(output_path, "w:bz2") as tar:
            tar.add(tmp_out, arcname="")

In redact_directory() replace:
redactions = self.redact_file(src_file, dest_file)


with:

if file_name.endswith(".tar.bz2"):
    print(f"[*] Processing nested archive: {src_file}")

    self.redact_nested_tar_bz2(
        src_file,
        dest_file
    )

    total_files += 1
    continue

redactions = self.redact_file(src_file, dest_file)

In main() replace:
if input_path.is_file() and (
    input_path.name.endswith(".tar.gz") or
    input_path.name.endswith(".tgz")
):


with:

if input_path.is_file() and (
    input_path.name.endswith(".tar.gz") or
    input_path.name.endswith(".tgz") or
    input_path.name.endswith(".tar.bz2")
):


Source file: lasso_reduction.py.

Then run:

python .\lasso_reduction.py -i .\input\lassoreport.tar.gz -o .\output\lassoreport_redacted.tar.gz


You should start seeing messages such as:

[*] Processing nested archive:
edb-lasso-report-ort1-...


which confirms the nested EDB Lasso bundles are actually being inspected rather than simply copied. lasso_reduction.py currently only processes the outer archive, which is why your run reported zero redactions.
