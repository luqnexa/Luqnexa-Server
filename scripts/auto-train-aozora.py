# SPDX-License-Identifier: AGPL-3.0-only
"""Automatically select, resume and train rights-cleared Aozora works locally."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import importlib.util
import io
import json
import math
from pathlib import Path
import sqlite3
import time
import urllib.parse
import urllib.request
import zipfile

spec = importlib.util.spec_from_file_location('literature', Path(__file__).with_name('train-literature.py'))
lit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lit)
CACHE = lit.ROOT / '.cache/aozora-auto'


def atomic(path, data):
    temporary = path.with_suffix(path.suffix + '.part')
    temporary.write_bytes(data)
    temporary.replace(path)


def valid_url(url):
    parsed = urllib.parse.urlsplit(url)
    return (parsed.scheme == 'https' and parsed.netloc == 'www.aozora.gr.jp'
            and parsed.path.startswith('/cards/') and parsed.path.endswith('.zip')
            and not parsed.query and not parsed.fragment)


def partition(rows):
    # Same author always in the same partition; no author-level train/test leakage.
    authors = ','.join(sorted({r['人物ID'] for r in rows}))
    value = int(hashlib.sha256(authors.encode()).hexdigest(), 16) % 10
    return 'test' if value == 0 else 'validation' if value == 1 else 'train'


def fingerprint(rows):
    return lit.sha(json.dumps(sorted(rows, key=lambda r: json.dumps(r, sort_keys=True)),
                              ensure_ascii=False, sort_keys=True).encode())


def database(path):
    db = sqlite3.connect(path)
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript('''
        CREATE TABLE IF NOT EXISTS works(id TEXT PRIMARY KEY, fingerprint TEXT, metadata TEXT);
        CREATE TABLE IF NOT EXISTS fragments(work TEXT, text TEXT, priority INTEGER);
        CREATE INDEX IF NOT EXISTS fragment_work ON fragments(work);
        CREATE INDEX IF NOT EXISTS fragment_text ON fragments(text);
    ''')
    return db


def ingest(db, sid, rows, data):
    archive = zipfile.ZipFile(io.BytesIO(data))
    names = [n for n in archive.namelist() if n.lower().endswith('.txt')]
    if len(names) != 1 or archive.getinfo(names[0]).file_size > 16 * 1024 * 1024:
        raise ValueError('Ambiguous or oversized text')
    original = archive.read(names[0]).decode('cp932')
    chunks = list(lit.sentences(lit.clean_aozora(original), 'ja'))
    if not chunks:
        raise ValueError('Empty body')
    part = partition(rows)
    row = rows[0]
    metadata = dict(id=sid, source='Aozora Bunko', title=row['作品名'],
                    contributors=rows, partition=part, sha256=lit.sha(data),
                    original_header=original.split('-'*20, 1)[0],
                    original_colophon=original[original.rfind('底本：'):] if '底本：' in original else '',
                    extracted_sentences=len(chunks))
    # Replace each work and its fragments in one transaction, including on revision.
    with db:
        db.execute('DELETE FROM fragments WHERE work=?', (sid,))
        db.executemany('INSERT INTO fragments VALUES(?,?,?)',
                       ((sid, text, ('test', 'validation', 'train').index(part)) for text in chunks))
        db.execute('INSERT OR REPLACE INTO works VALUES(?,?,?)',
                   (sid, fingerprint(rows), json.dumps(metadata, ensure_ascii=False)))


def train(db, output, index_hash, summary):
    counts = Counter()
    sizes = Counter()
    # Deduplicate across all books, held-out partitions take precedence.
    for text, priority in db.execute('SELECT text, MIN(priority) FROM fragments GROUP BY text'):
        part = ('test', 'validation', 'train')[priority]
        sizes[part] += 1
        if part == 'train':
            counts.update(lit.trainer.features(text))
    retained = sorted((key, count) for key, count in
                      sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:200000]
                      if count >= 3)
    if not retained:
        raise ValueError('No usable training features')
    model = lit.trainer.encode(retained)
    table = dict(retained)
    def score(text):
        return sum(math.log1p(table.get(key, 0)) * (128 if key[0] == lit.trainer.BI else 768)
                   for key in lit.trainer.features(text)) / len(text)
    wins = ties = pairs = 0
    for (text,) in db.execute('SELECT text FROM fragments GROUP BY text HAVING MIN(priority)=0 ORDER BY text LIMIT 5000'):
        pos = len(text) // 2
        if text[pos] == text[pos-1]:
            continue
        bad = text[:pos-1] + text[pos] + text[pos-1] + text[pos+1:]
        delta = score(text) - score(bad)
        pairs += 1
        wins += delta > 0
        ties += delta == 0
    report = dict(source='https://www.aozora.gr.jp/', index_sha256=index_hash,
                  metadata_license='CC BY 4.0; attribution: Aozora Bunko',
                  rules='https://www.aozora.gr.jp/guide/kijyunn.html',
                  rights_policy='Single-author works only; every contributor must be that author with both copyright flags なし; translations excluded.',
                  preprocessing='Remove notation guide, ruby, annotations and colophon; whitespace normalization; <=160 character fragments; global deduplication; author-level holdout.',
                  partitions=dict(sizes), retained_features=len(retained),
                  model_bytes=len(model), model_sha256=lit.sha(model), **summary,
                  evaluation=dict(task='Held-out original vs adjacent swap; NOT IME accuracy',
                                  sample='First 5000 sorted test fragments', pairs=pairs,
                                  wins=wins, ties=ties, losses=pairs-wins-ties),
                  works=[json.loads(r[0]) for r in db.execute('SELECT metadata FROM works ORDER BY id')],
                  activation='Staged only; existing installed IME and bundled English model remain in use. No conversion accuracy claim.')
    # Publish immutable content-addressed model; latest pointer is the atomic switch.
    release = output / report['model_sha256']
    release.mkdir(parents=True, exist_ok=True)
    atomic(release / 'context-literature.bin', model)
    atomic(release / 'literature-training.json', json.dumps(report, ensure_ascii=False, indent=2).encode())
    atomic(output / 'latest.json', json.dumps(dict(model=str(release / 'context-literature.bin'),
           report=str(release / 'literature-training.json'), sha256=lit.sha(model))).encode())
    print(json.dumps({k: v for k, v in report.items() if k != 'works'}, ensure_ascii=True), flush=True)


def request(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'NextIME-corpus-research/0.2'})
    with urllib.request.urlopen(req, timeout=60) as response:
        if urllib.parse.urlsplit(response.url).netloc != 'www.aozora.gr.jp':
            raise ValueError('Unexpected redirect host')
        data = response.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024:
        raise ValueError('Oversized download')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download', action='store_true')
    parser.add_argument('--refresh-index', action='store_true')
    parser.add_argument('--max-books', type=int, default=0, help='0: all eligible works; limit newly processed works per run')
    args = parser.parse_args()
    if args.max_books < 0:
        parser.error('--max-books must be nonnegative')
    CACHE.mkdir(parents=True, exist_ok=True)
    # OS releases this lock on exit/crash; concurrent writers cannot corrupt checkpoints.
    with (CACHE / 'run.lock').open('a+b') as lock:
        lock.seek(0)
        if lock.read(1) == b'':
            lock.write(b'0'); lock.flush()
        lock.seek(0)
        try:
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except ImportError:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        index_path = CACHE / 'index.zip'
        if args.refresh_index or not index_path.exists():
            if args.download:
                atomic(index_path, request(lit.INDEX))
            elif (lit.CACHE / 'aozora-index.zip').exists() and not args.refresh_index:
                atomic(index_path, (lit.CACHE / 'aozora-index.zip').read_bytes())
            else:
                parser.error('Index missing or refresh requested; use --download')
        index = index_path.read_bytes()
        with zipfile.ZipFile(io.BytesIO(index)) as archive:
            names = [n for n in archive.namelist() if n.endswith('.csv')]
            if len(names) != 1 or archive.getinfo(names[0]).file_size > 64 * 1024 * 1024:
                raise ValueError('Invalid catalogue')
            catalog = defaultdict(list)
            for row in csv.DictReader(io.StringIO(archive.read(names[0]).decode('utf-8-sig'))):
                catalog[row['作品ID']].append(row)
        eligible = {sid: rows for sid, rows in catalog.items()
                    if lit.allowed_aozora(rows) and valid_url(rows[0]['テキストファイルURL'])
                    and len({r['人物ID'] for r in rows}) == 1}
        db = database(CACHE / 'progress.sqlite3')
        # Removed/restricted/revised works cannot survive from an older index.
        with db:
            for sid, old in db.execute('SELECT id,fingerprint FROM works').fetchall():
                if sid not in eligible or fingerprint(eligible[sid]) != old:
                    db.execute('DELETE FROM works WHERE id=?', (sid,))
                    db.execute('DELETE FROM fragments WHERE work=?', (sid,))
        done = {row[0] for row in db.execute('SELECT id FROM works')}
        processed = 0
        errors = {}
        consecutive = 0
        # Reuse the already reviewed cached works first, then catalogue order.
        ordered = sorted(eligible, key=lambda sid: (sid not in lit.AOZORA, sid))
        print(f'Eligible: {len(eligible)}, resumed: {len(done)}', flush=True)
        output = CACHE / 'releases'
        output.mkdir(exist_ok=True)
        def publish():
            if db.execute('SELECT COUNT(*) FROM works').fetchone()[0]:
                train(db, output, lit.sha(index), dict(eligible_books=len(eligible),
                      completed_books=db.execute('SELECT COUNT(*) FROM works').fetchone()[0],
                      rejected_books=len(catalog)-len(eligible), errors=errors,
                      pending_books=len(eligible)-db.execute('SELECT COUNT(*) FROM works').fetchone()[0]))
        try:
            for sid in ordered:
                if sid in done:
                    continue
                if args.max_books and processed >= args.max_books:
                    break
                rows = eligible[sid]
                # Cache key binds both URL and complete catalogue metadata.
                cached = CACHE / (sid + '-' + fingerprint(rows) + '.zip')
                try:
                    if cached.exists():
                        data = cached.read_bytes()
                    elif sid in lit.AOZORA and (lit.CACHE / f'aozora-{sid}.zip').exists():
                        old_report = json.loads((lit.ROOT / 'models/literature-training.json').read_text(encoding='utf-8'))
                        provenance = next((w for w in old_report['works'] if w['id'] == sid), None)
                        data = (lit.CACHE / f'aozora-{sid}.zip').read_bytes()
                        if (not provenance or provenance['download'] != rows[0]['テキストファイルURL']
                                or provenance['sha256'] != lit.sha(data) or old_report['index_sha256'] != lit.sha(index)):
                            if not args.download:
                                continue
                            time.sleep(1)
                            data = request(rows[0]['テキストファイルURL'])
                        atomic(cached, data)
                    elif args.download:
                        time.sleep(1)  # Sequential requests, no parallel crawl.
                        data = request(rows[0]['テキストファイルURL'])
                        atomic(cached, data)
                    else:
                        continue
                    ingest(db, sid, rows, data)
                    consecutive = 0
                except (ValueError, OSError, zipfile.BadZipFile, UnicodeError) as error:
                    errors[sid] = str(error)
                    consecutive = consecutive + 1 if isinstance(error, OSError) else 0
                    print(f'Skip {sid}: {error}', flush=True)
                    if consecutive >= 10:
                        raise RuntimeError('Ten consecutive failures; stopping to avoid repeated server requests') from error
                processed += 1
                if processed % 100 == 0:
                    publish()
            publish()
        finally:
            atomic(CACHE / 'status.json', json.dumps(dict(processed_this_run=processed,
                   completed_books=db.execute('SELECT COUNT(*) FROM works').fetchone()[0],
                   eligible_books=len(eligible), errors=errors,
                   pending_books=len(eligible)-db.execute('SELECT COUNT(*) FROM works').fetchone()[0]),
                   ensure_ascii=False, indent=2).encode())
            db.close()


if __name__ == '__main__':
    main()
