import tempfile
import unittest
from pathlib import Path

from check_markdown_links import check_file


class MarkdownLinksTests(unittest.TestCase):
    def test_relative_root_angle_and_reference_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a b.md").write_text("# Target", encoding="utf-8")
            page = root / "index.md"
            page.write_text('[a](<a b.md>) [b](/a%20b.md#target) [c][id]\n[id]: <a b.md>\n', encoding="utf-8")
            self.assertEqual(check_file(page, root), [])

    def test_missing_file_reference_and_escape_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "index.md"
            page.write_text('[a](missing.md) [b](../escape.md) [c][undefined]', encoding="utf-8")
            self.assertEqual(len(check_file(page, root)), 3)

    def test_code_and_external_links_are_not_fetched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "index.md"
            page.write_text('```md\n[a](example.md)\n```\n[a](https://example.invalid/) [b](#here)', encoding="utf-8")
            self.assertEqual(check_file(page, root), [])


if __name__ == "__main__":
    unittest.main()
