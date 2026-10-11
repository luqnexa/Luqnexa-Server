# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('auto', Path(__file__).with_name('auto-train-aozora.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def rows(author='1'):
    return [dict(人物ID=author, 作品名='試験', 作品著作権フラグ='なし',
                 人物著作権フラグ='なし', 役割フラグ='著者',
                 テキストファイルURL='https://www.aozora.gr.jp/cards/1/test.zip')]


def book(body):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('text.txt', ('題名\n'+'-'*30+'\n説明\n'+'-'*30+'\n'+body+'\n底本：試験').encode('cp932'))
    return buffer.getvalue()


class AutoTests(unittest.TestCase):
    def test_url_and_rights(self):
        self.assertTrue(module.valid_url(rows()[0]['テキストファイルURL']))
        for url in ('http://www.aozora.gr.jp/cards/a.zip',
                    'https://www.aozora.gr.jp.evil.test/cards/a.zip',
                    'https://www.aozora.gr.jp/cards/a.zip?x=1'):
            self.assertFalse(module.valid_url(url))
        protected = dict(rows()[0], 人物著作権フラグ='あり')
        self.assertFalse(module.lit.allowed_aozora(rows()+[protected]))

    def test_stable_author_split_and_revision(self):
        self.assertEqual(module.partition(rows()), module.partition([dict(rows()[0], 作品名='別作品')]))
        self.assertNotEqual(module.fingerprint(rows()), module.fingerprint([dict(rows()[0], 作品名='別作品')]))
        with tempfile.TemporaryDirectory() as directory:
            db = module.database(Path(directory)/'progress.db')
            module.ingest(db, '1', rows(), book('古い文章です。'))
            module.ingest(db, '1', rows(), book('新しい文章です。'))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM works').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT text FROM fragments').fetchone()[0], '新しい文章です。')
            with self.assertRaises(ValueError):
                module.ingest(db, '1', rows(), book(''))
            self.assertEqual(db.execute('SELECT text FROM fragments').fetchone()[0], '新しい文章です。')
            db.close()
            db = module.database(Path(directory)/'progress.db')
            self.assertEqual(db.execute('SELECT fingerprint FROM works').fetchone()[0], module.fingerprint(rows()))
            self.assertEqual(db.execute('SELECT text FROM fragments').fetchone()[0], '新しい文章です。')
            db.close()

    def test_holdout_dedup_and_atomic_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            db = module.database(output/'progress.db')
            train_author = next(str(n) for n in range(100) if module.partition(rows(str(n))) == 'train')
            module.ingest(db, '1', rows(train_author), book('自然な文章です。'*8))
            db.execute('INSERT INTO fragments VALUES(?,?,?)', ('heldout', '自然な文章です。', 0))
            module.ingest(db, '2', rows(train_author), book(''.join(c+'日本語を学習します。' for c in '甲乙丙丁')))
            db.commit()
            module.train(db, output, 'a'*64, {})
            latest = json.loads((output/'latest.json').read_text())
            binary = Path(latest['model']).read_bytes()
            report = json.loads(Path(latest['report']).read_text(encoding='utf-8'))
            self.assertEqual(module.lit.sha(binary), latest['sha256'])
            self.assertEqual(report['partitions'], {'test': 1, 'train': 4})
            retained = set(module.lit.trainer.features('自然な文章です。')) - set(
                key for c in '甲乙丙丁' for key in module.lit.trainer.features(c+'日本語を学習します。'))
            import struct
            keys = {struct.unpack('<IIII', binary[i:i+16])[:3] for i in range(8,len(binary),16)}
            self.assertTrue(retained.isdisjoint(keys))
            self.assertEqual(len(binary), 8+16*report['retained_features'])
            db.close()


if __name__ == '__main__':
    unittest.main()
