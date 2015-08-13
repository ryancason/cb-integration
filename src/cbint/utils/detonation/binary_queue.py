__author__ = 'jgarman'

import os, sqlite3
from time import sleep
import threading
import datetime
import flask
try:
    import simplejson as json
except ImportError:
    import json


class SqliteQueue(object):
    _create_queue = '''CREATE TABLE IF NOT EXISTS binary_data (
  md5sum                 VARCHAR(32) PRIMARY KEY NOT NULL,
  -- timestamps
  last_modified          DATETIME,
  inserted_at            DATETIME,
  next_attempt_at        DATETIME,
  binary_available_since DATETIME,
  -- results
  short_result           TEXT,            -- this can be an error if the state is an error state
  detailed_result        TEXT,            -- we convert to HTML before storing in here
  score                  INTEGER,
  iocs                   TEXT,            -- this is just a dump of JSON data
  -- state
  state                  INTEGER,         -- define states below
  analysis_version       INTEGER
);
'''
    _create_metadata = '''CREATE TABLE IF NOT EXISTS feed_data (
  full_name        TEXT,
  short_name       TEXT,
  tech_detail      TEXT,
  big_icon         TEXT,
  small_icon       TEXT,
  -- versioning
  database_version INTEGER,
  feed_version     INTEGER,
  analysis_version INTEGER                 -- the current "analysis" version. we can re-analyze things in the background
);
'''
    _append = 'INSERT INTO binary_data (md5sum, last_modified, inserted_at, state) VALUES (?, ?, ?, 0)'
    _write_lock = 'BEGIN IMMEDIATE'
    _popleft_get = (
            'SELECT md5sum FROM binary_data WHERE state = 0 AND (next_attempt_at < ? OR next_attempt_at IS NULL)'
            'ORDER BY binary_available_since DESC,next_attempt_at ASC LIMIT 1'
            )
    _update_queue = 'UPDATE binary_data SET state=50,last_modified = ? WHERE md5sum = ?'
    _all_analyzed = 'SELECT * FROM binary_data WHERE state = 100'
    _update_binary_availability = 'UPDATE binary_data SET last_modified = ?,binary_available_since = ? WHERE md5sum = ?'
    _update_binary_state = ('UPDATE binary_data SET last_modified = ?,next_attempt_at = ?,short_result = ?,'
                            'detailed_result = ?,score = ?,state = ?,analysis_version = ? WHERE md5sum = ?')
    _reprocess_binaries_on_restart = 'UPDATE binary_data SET state = 0 WHERE state = 50'
    _add_iocs = 'UPDATE binary_data SET iocs = ? WHERE md5sum = ?'

    _current_db_version = 2

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self._connection_cache = {}

        with self._get_conn() as conn:
            conn.execute(self._create_queue)
            conn.execute(self._create_metadata)

            cur = conn.cursor()
            cur.execute("SELECT database_version FROM feed_data")
            res = cur.fetchone()
            if not res:
                # we've never used this database before, set the database version and feed information
                pass
            else:
                (version,) = res
                # TODO: database migrations

    def _get_conn(self):
        id = threading.current_thread().ident
        if id not in self._connection_cache:
            self._connection_cache[id] = sqlite3.Connection(self.path,
                    timeout=60)
            self._connection_cache[id].row_factory = sqlite3.Row
        return self._connection_cache[id]

    def append(self, md5sum, file_available=False):
        # returns True if a new item was created, False otherwise
        now = datetime.datetime.now()
        with self._get_conn() as conn:
            try:
                conn.execute(self._append, (md5sum, now, now))
            except sqlite3.IntegrityError:
                conn.commit() # unlock the database
                return False

            if file_available:
                self.set_binary_available(md5sum, now)

        return True

    def set_binary_available(self, md5sum, as_of=None):
        now = datetime.datetime.now()
        if not as_of:
            as_of = now
        with self._get_conn() as conn:
            conn.execute(self._update_binary_availability, (now, as_of, md5sum))

    def add_iocs(self, md5sum, iocs):
        ioc_string = json.dumps(iocs)
        with self._get_conn() as conn:
            conn.execute(self._add_iocs, (ioc_string, md5sum))

    def mark_as_analyzed(self, md5sum, succeeded, analysis_version, short_result, long_result, score=0, retry_at=None):
        print 'marking as analyzed: %s as %s: version %s, results: %s/%s, score: %d. retry? %s' % (
            md5sum, succeeded, analysis_version, short_result, long_result, score, retry_at
        )
        if not succeeded:
            # mark state as an error state. if we never want to retry, it's permanent.
            if not retry_at:
                state = 1
            else:
                state = 0
        else:
            state = 100

        with self._get_conn() as conn:
            conn.execute(self._update_binary_state, (datetime.datetime.now(), retry_at, short_result, long_result,
                                                     score, state, analysis_version, md5sum))

    def get(self, sleep_wait=True):
        keep_pooling = True
        wait = 0.1
        max_wait = 2
        tries = 0
        with self._get_conn() as conn:
            md5sum = None
            while keep_pooling:
                conn.execute(self._write_lock)
                cursor = conn.execute(self._popleft_get, (datetime.datetime.now(),))
                try:
                    md5sum, = cursor.next()
                    keep_pooling = False
                except StopIteration:
                    conn.commit() # unlock the database
                    if not sleep_wait:
                        keep_pooling = False
                        continue
                    tries += 1
                    sleep(wait)
                    wait = min(max_wait, tries/10 + wait)
            if md5sum:
                conn.execute(self._update_queue, (datetime.datetime.now(), md5sum))
                conn.commit()
                return md5sum
        return None

    def reprocess_on_restart(self):
        with self._get_conn() as conn:
            conn.execute(self._reprocess_binaries_on_restart)


class SqliteFeedServer(threading.Thread):
    _get_feed_contents = 'SELECT * FROM binary_data'

    def __init__(self, dbname):
        threading.Thread.__init__(self)
        self.daemon = True
        self.dbname = dbname

        self.app = flask.Flask(__name__, template_folder='templates')
        self.app.add_url_rule("/binaries.html", view_func=self.binary_results, methods=['GET'])

    def binary_results(self):
        cur = self.conn.cursor()
        cur.execute(self._get_feed_contents)
        binaries = cur.fetchall()
        return flask.render_template('binaries.html', binaries=binaries, integration_name='test_feed')

    def run(self):
        self.conn = sqlite3.Connection(self.dbname, timeout=60)
        self.conn.row_factory = sqlite3.Row

        self.app.run(host='127.0.0.1', port=8080, debug=True, use_reloader=False)
