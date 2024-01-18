from collections import namedtuple
from dataclasses import dataclass
import datetime
from enum import Enum
from fnmatch import fnmatch
import json
from pathlib import Path
import time
from typing import Annotated, Callable, Iterable, Iterator, Literal, Optional, TypeVar
from urllib.parse import urldefrag

from bs4 import BeautifulSoup
from charset_normalizer import from_bytes, is_binary
from retry import retry
import apsw
import apsw.bestpractice
import apsw.ext
import httpx
import kdl
import pytimeparse
import rich.console
import rich.progress
import rich.table
import rich.traceback
import rich.live
import rich.tree
import rich.panel
import rich.pretty
import structlog
import typer

rich.traceback.install(show_locals=True)
log: structlog.PrintLogger = structlog.get_logger()

apsw.bestpractice.apply(apsw.bestpractice.recommended)

app = typer.Typer()
console = rich.console.Console()
err_console = rich.console.Console(stderr=True)

last_fetch: datetime.datetime | None = None


@dataclass(frozen=True)
class UrlRule:
    pattern: str | None
    query_key: str | None

    def __repr__(self):
        if self.query_key is not None:
            return f'UrlRule(query_key={self.query_key!r})'
        if self.pattern is not None:
            return f'UrlRule({self.pattern!r})'
        return 'UrlRule()'

    @staticmethod
    def from_kdl(obj: kdl.types.Node) -> 'UrlRule':
        pattern = obj.args[0] if obj.args else None
        return UrlRule(pattern=pattern, query_key=obj.props.get('query-key'))

    def match(self, url: httpx.URL) -> bool:
        if self.pattern:
            if fnmatch(str(url), self.pattern):
                return True
        elif self.query_key:
            if self.query_key in url.params:
                return True
        return False


@dataclass
class Authentication:
    fields: dict[str, str]
    method: str
    action: httpx.URL

    @staticmethod
    def from_kdl(obj: kdl.types.Node) -> 'Authentication':
        method = obj.props['method']
        action = httpx.URL(obj.props['action'])
        fields = {}
        for field in obj.getAll('field'):
            fields.update(field.props)
        return Authentication(method=method, action=action, fields=fields)


@dataclass
class UnauthorizationRule:
    body: str

    @staticmethod
    def from_kdl(obj: kdl.types.Node) -> 'UnauthorizationRule':
        return UnauthorizationRule(body=obj.props['body'])


@dataclass
class ConfigSite:
    name: str
    include_rules: list[UrlRule]
    exclude_rules: list[UrlRule]
    start_url: httpx.URL
    fetch_delay: datetime.timedelta
    authentication: Authentication | None
    unauthorized_when: list[UnauthorizationRule]

    @staticmethod
    def from_kdl(obj: kdl.types.Node) -> 'ConfigSite':
        fetch_delay_node = obj.get('fetch-delay')

        fetch_delay_value = fetch_delay_node.args[0] if fetch_delay_node else '1s'
        if isinstance(fetch_delay_value, float):
            fetch_delay_value = f'{fetch_delay_value}s'
        fetch_delay = datetime.timedelta(seconds=pytimeparse.parse(fetch_delay_value) or 60)

        start_url = obj.get('start-url')
        assert start_url, 'a start-url node is required'
        auth = obj.get('authentication')
        return ConfigSite(
            name=obj.args[0],
            start_url=httpx.URL(start_url.args[0]),
            include_rules=[UrlRule.from_kdl(node) for node in obj.getAll('include-rule')],
            exclude_rules=[UrlRule.from_kdl(node) for node in obj.getAll('exclude-rule')],
            fetch_delay=fetch_delay,
            authentication=Authentication.from_kdl(auth) if auth else None,
            unauthorized_when=[UnauthorizationRule.from_kdl(node) for node in obj.getAll('unauthorized-when')],
        )

    def match_url(self, url: httpx.URL) -> bool:
        # log.info(f'validating {url}')
        for rule in self.exclude_rules:
            if rule.match(url):
                # log.error(f'  ❌ excluding due to matched rule {rule}')
                return False
            # log.debug(f'  ✅ url did not match {rule}')

        for rule in self.include_rules:
            if rule.match(url):
                # log.debug(f'  ✅ url matched {rule}')
                return True
            # log.warn(f'  🟨 url did not match {rule}')

        # log.error('  ❌ excluding as no inclusion rules matched')
        return False


@dataclass
class Config:
    sites: list[ConfigSite]

    @staticmethod
    def from_kdl(obj: kdl.types.Document) -> 'Config':
        return Config(sites=[ConfigSite.from_kdl(node) for node in obj.getAll('site')])


def kdl_url(obj: kdl.types.Value, fragment: kdl.errors.ParseFragment):
    assert isinstance(obj, kdl.types.String), 'expected a valid urlmatch pattern'
    return httpx.URL(obj.value)


def kdl_urlpattern(obj: kdl.types.Value, fragment: kdl.errors.ParseFragment):
    assert isinstance(obj, kdl.types.String), 'expected a valid urlmatch pattern'
    return obj.value


def parse_config(config_file: Path) -> Config:
    parseconfig = kdl.parsing.ParseConfig(
        valueConverters={
            'url': kdl_url,
            'urlpattern': kdl_urlpattern,
        },
    )
    kdl_config = kdl.parsefuncs.parse(config_file.read_text(), parseconfig)
    return Config.from_kdl(kdl_config)


def ensure_schema(db: apsw.Connection):
    # a new database starts at user_version 0
    if db.pragma('user_version') == 0:
        with db:
            db.execute(
                """
                CREATE TABLE link (id INTEGER PRIMARY KEY AUTOINCREMENT, url text NOT NULL, should_fetch int NOT NULL DEFAULT 0);
                CREATE UNIQUE INDEX link_url_uidx ON link(url);
                CREATE VIEW fetch_queue AS SELECT id, url FROM link WHERE should_fetch = 1 AND NOT EXISTS (SELECT * FROM request WHERE link_id = link.id);
                CREATE TABLE sitemap (source int NOT NULL REFERENCES link(id), target int NOT NULL REFERENCES link(id), PRIMARY KEY (source, target));
                CREATE TABLE request (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    link_id int NOT NULL REFERENCES link(id),
                    method text NOT NULL,
                    url text NOT NULL,
                    headers json NOT NULL,
                    body blob
                );
                CREATE INDEX request_link_id ON request(link_id);
                CREATE TABLE response (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    link_id int NOT NULL REFERENCES link(id),
                    request_id int NOT NULL REFERENCES request(id),
                    status_code text NOT NULL,
                    url text NOT NULL,
                    headers json NOT NULL,
                    encoding text NOT NULL,
                    body blob NOT NULL,
                    parsed int NOT NULL DEFAULT 0
                );
                CREATE INDEX response_is_parsed ON response(parsed) WHERE parsed = 0;
                CREATE VIEW parse_queue AS SELECT id FROM response WHERE parsed = 0;
                PRAGMA user_version = 1;
                """
            )

    if db.pragma('user_version') == 1:
        with db:
            db.execute(
                """
                DROP VIEW parse_queue;
                CREATE VIEW parse_queue AS SELECT id FROM response WHERE parsed = 0 AND body IS NOT NULL;
                PRAGMA user_version = 2;
                """
            )

    if db.pragma('user_version') == 2:
        with db:
            db.execute(
                """
                DROP VIEW parse_queue;
                CREATE VIEW parse_queue AS SELECT id, url FROM response WHERE parsed = 0 AND body IS NOT NULL;
                PRAGMA user_version = 3;
                """
            )

    if db.pragma('user_version') == 3:
        with db:
            db.execute(
                """
                CREATE INDEX response_request_id_idx ON response(request_id); --> request(id)
                CREATE INDEX response_link_id_idx ON response(link_id); --> link(id)
                CREATE INDEX sitemap_target_idx ON sitemap(target); --> link(id)
                PRAGMA user_version = 4;
                """
            )

    if db.pragma('user_version') == 4:
        with db:
            log.info('updating "request" table')

            before = db.execute('SELECT sum(length(headers)) AS size FROM request').fetchone()
            assert before
            db.execute('UPDATE request SET headers = jsonb(headers);')
            after = db.execute('SELECT sum(length(headers)) AS size FROM request').fetchone()
            assert after
            log.info(f'"request" table went from {before.size:,} bytes to {after.size:,} bytes')

            log.info('updating "response" table')
            before = db.execute('SELECT sum(length(headers)) AS size FROM response').fetchone()
            assert before
            db.execute('UPDATE response SET headers = jsonb(headers);')
            after = db.execute('SELECT sum(length(headers)) AS size FROM response').fetchone()
            assert after
            log.info(f'"response" table went from {before.size:,} bytes to {after.size:,} bytes')

            log.info('update complete! completing tx')
            db.execute('PRAGMA user_version = 5;')
        log.info('tx complete!')


def connect(database_file: Path, *, check: None | Literal['quick'] | Literal['full'] = None):
    connection = apsw.Connection(str(database_file))
    connection.row_trace = apsw.ext.DataClassRowFactory()

    if check == 'quick':
        # Useful at startup to detect some database corruption
        log.info('executing quick_check on database')
        result = connection.pragma('quick_check')
        if result != 'ok':
            print('Quick check errors', result)
    elif check == 'full':
        log.info('executing integrity_check on database')
        result = connection.pragma('integrity_check')
        if result != 'ok':
            print('Integrity check errors', result)

    ensure_schema(connection)
    return connection


retry_on_busy = retry(apsw.BusyError, delay=0.1, jitter=(0, 0.2), max_delay=2, tries=10)
retry_on_connectionerror = retry(
    (httpx.RemoteProtocolError, httpx.ReadTimeout), delay=1, jitter=(0, 5), max_delay=30, tries=10
)

ReadableFile = typer.Option(exists=True, file_okay=True, dir_okay=False, writable=False, readable=True)
WritableFile = typer.Option(file_okay=True, dir_okay=False, writable=True, readable=True)


QueuedUrl = namedtuple('QueuedUrl', ['url', 'id'])
UnparsedResponseId = namedtuple('UnparsedResponseId', ['id'])
UrlAndFetch = namedtuple('UrlAndFetch', ['url', 'should_fetch', 'base_url'])
UrlBodyAndEncoding = namedtuple('UrlBodyAndEncoding', ['url', 'body', 'encoding'])
ResponseUrl = namedtuple('ResponseUrl', ['url'])


class DebugLevel(str, Enum):
    error = 'error'
    warning = 'warning'
    debug = 'debug'
    info = 'info'


@retry_on_busy
def insert_link(db: apsw.Connection, url: httpx.URL, should_fetch: bool = True) -> int:
    # log.info(f'trying to insert {url!r}')
    with db:
        row = db.execute(
            """
            INSERT INTO link (url, should_fetch)
            VALUES (:url, :should_fetch)
            ON CONFLICT DO UPDATE SET url = :url
            RETURNING id
            """,
            dict(url=str(url), should_fetch=should_fetch),
        ).fetchone()
        assert row
        return row.id


def detect_encoding_or_binary(content: bytes) -> str:
    if is_binary(content):
        return 'binary'
    return getattr(from_bytes(content).best(), 'encoding', 'unknown')


def record_http_request(db: apsw.Connection, *, link_id: int, request: httpx.Request) -> int:
    with db:
        content = request.read() or None
        request_row = db.execute(
            """
            INSERT INTO request(link_id, method, url, headers, body)
            VALUES (:link_id, :method, :url, jsonb(:headers), :body)
            RETURNING id
            """,
            dict(
                link_id=link_id,
                method=str(request.method),
                url=str(request.url),
                headers=json.dumps(dict(request.headers.items()), sort_keys=True, separators=(',', ':')),
                body=content,
            ),
        ).fetchone()
        assert request_row
        return request_row.id


def record_http_response(
    db: apsw.Connection,
    *,
    link_id: int,
    request_id: int,
    response: httpx.Response,
    unauthorization_rules: list[UnauthorizationRule],
) -> int:
    with db:
        content = response.read()
        encoding = detect_encoding_or_binary(content)

        headers = dict(response.headers.items())
        if 'report-to' in headers:
            del headers['report-to']
        if 'nel' in headers:
            del headers['nel']
        if 'cf-ray' in headers:
            del headers['cf-ray']

        if headers.get('server') == 'cloudflare' and headers.get('location') == '/err429.html':
            response.status_code = 429
            response.raise_for_status()
            assert False, 'we should not be at this point'

        if unauthorization_rules:
            response_text = response.text
            if any(rule.body in response_text for rule in unauthorization_rules):
                # certain sites return 200 for "you need to log in."
                # if we're configured to do so, overwrite the 200 with a 401 and raise an error
                response.status_code = 401
                response.raise_for_status()
                assert False, 'we should not be at this point'

        response_row = db.execute(
            """
            INSERT INTO response(link_id, request_id, status_code, url, headers, body, encoding)
            VALUES (:link_id, :request_id, :status_code, :url, jsonb(:headers), :body, :encoding)
            RETURNING id
            """,
            dict(
                link_id=link_id,
                request_id=request_id,
                status_code=response.status_code,
                url=str(response.url),
                headers=json.dumps(headers, sort_keys=True, separators=(',', ':')),
                body=content or b'',
                encoding=encoding,
            ),
        ).fetchone()
        assert response_row
        return response_row.id


@retry_on_busy
def record_http_pair(
    db: apsw.Connection, *, link_id: int, response: httpx.Response, unauthorization_rules: list[UnauthorizationRule]
) -> None:
    with db:
        request_id = record_http_request(db, link_id=link_id, request=response.request)

        for r in [*response.history, response]:
            record_http_response(
                db, link_id=link_id, request_id=request_id, response=r, unauthorization_rules=unauthorization_rules
            )


@retry_on_busy
def next_in_fetch_queue(db: apsw.Connection) -> QueuedUrl | None:
    with db:
        return db.execute('SELECT id, url FROM fetch_queue').fetchone()


@retry_on_busy
def next_in_parse_queue(db: apsw.Connection) -> QueuedUrl | None:
    with db:
        return db.execute('SELECT id, url FROM parse_queue').fetchone()


@retry_on_busy
def mark_response_as_parsed(db: apsw.Connection, *, response_id: int) -> UnparsedResponseId | None:
    with db:
        return db.execute('UPDATE response SET parsed = 1 WHERE id = :id', dict(id=response_id)).fetchone()


def progress_bar(*, transient: bool):
    return rich.progress.Progress(
        rich.progress.SpinnerColumn(),
        rich.progress.TextColumn('[progress.description]{task.description}'),
        rich.progress.BarColumn(),
        rich.progress.TaskProgressColumn(),
        rich.progress.MofNCompleteColumn(),
        rich.progress.TimeElapsedColumn(),
        rich.progress.TimeRemainingColumn(),
        transient=transient,
    )


def extract_links(*, db: apsw.Connection, config: ConfigSite, batch_size: int = 100) -> None:
    with db:
        pending_parse: list[QueuedUrl] = list(db.execute(f'SELECT url, id FROM parse_queue LIMIT {batch_size}'))

    with progress_bar(transient=True) as progress:
        task = progress.add_task('[red]Parsing...', total=len(pending_parse))

        for record in pending_parse:
            base_url = record.url
            progress.update(task, description=f'[cyan] PARSE {base_url}')

            with db:
                insert_link(db, base_url)

                unique_links = parse_response_for_links(db, response_id=record.id)
                for link in unique_links:
                    should_fetch = config.match_url(link)
                    insert_link(db, link, should_fetch)
                    update_sitemap(db, source=base_url, target=link)

                mark_response_as_parsed(db, response_id=record.id)

            progress.update(task, advance=1)


@retry_on_connectionerror
def get_document(*, client: httpx.Client, url: httpx.URL | str) -> httpx.Response:
    return client.get(url)


@retry_on_connectionerror
def authenticate(*, config: ConfigSite, client: httpx.Client) -> httpx.Response:
    assert config.authentication, 'config.authentication must be set'
    log.info(f'authenticating with {config.authentication.action}')
    if config.authentication.method != 'post':
        raise ValueError('we only know how to handle post requests')
    return client.post(config.authentication.action, data=config.authentication.fields)


def delay_urlfetch(*, config: ConfigSite) -> None:
    time.sleep(config.fetch_delay.total_seconds())
    return

    global last_fetch
    if last_fetch is None:
        # just update the last_fetch time
        last_fetch = datetime.datetime.now()
    elif (datetime.datetime.now() - last_fetch) <= config.fetch_delay:
        # calculate how much time is remaining
        # remaining = config.fetch_delay - (datetime.datetime.now() - last_fetch)
        # if remaining.total_seconds() > 0:
        #     # delay the next fetch
        #     time.sleep(remaining.total_seconds())
        # and update the last_fetch time

        time.sleep(config.fetch_delay.total_seconds())
        last_fetch = datetime.datetime.now()


def fetch_url(
    *,
    client: httpx.Client,
    source_link_id: int,
    url: httpx.URL | str,
    db: apsw.Connection,
    config: ConfigSite,
    is_retry: bool = False,
) -> None:
    try:
        r = get_document(client=client, url=url)
        record_http_pair(db, link_id=source_link_id, response=r, unauthorization_rules=config.unauthorized_when)
    except httpx.HTTPStatusError as http_error:
        if is_retry:
            raise http_error

        if http_error.response.status_code == 429:
            log.info('got a 429; sleeping for 5 minutes')
            time.sleep(300)
            fetch_url(
                client=client,
                source_link_id=source_link_id,
                url=url,
                db=db,
                config=config,
                is_retry=True,
            )

        if config.authentication:
            authenticate(client=client, config=config)
            fetch_url(
                client=client,
                source_link_id=source_link_id,
                url=url,
                db=db,
                config=config,
                is_retry=True,
            )
        else:
            raise http_error


def fetch_documents(*, db: apsw.Connection, config: ConfigSite, client: httpx.Client, batch_size: int = 50) -> None:
    with db:
        pending_fetch: list[QueuedUrl] = list(db.execute(f'SELECT id, url FROM fetch_queue LIMIT {batch_size}'))

    with progress_bar(transient=True) as progress:
        task = progress.add_task('[green]Fetching...', total=len(pending_fetch))

        for queued in pending_fetch:
            progress.stop_task(task)
            progress.update(task, description=f'[yellow] WAIT  {queued.url}')
            delay_urlfetch(config=config)
            progress.start_task(task)

            progress.update(task, description=f'[green] GET   {queued.url}')

            fetch_url(
                client=client,
                url=queued.url,
                source_link_id=queued.id,
                db=db,
                config=config,
            )

            progress.update(task, advance=1)


def init_client() -> httpx.Client:
    cookies = httpx.Cookies()
    headers = {'user-agent': 'story-archiver (stories@hawkrives.fastmail.fm)'}
    timeout = httpx.Timeout(10, read=30)
    return httpx.Client(http2=True, follow_redirects=True, cookies=cookies, headers=headers, timeout=timeout)


def parse_body_for_links(*, body: bytes, encoding: str, base_url: httpx.URL) -> Iterator[httpx.URL]:
    # log.info('parse_body_for_links')
    soup = BeautifulSoup(body.decode(encoding), 'lxml')
    # log.info('decoded')
    for link in soup.select('a[href]'):
        # log.info('in soup')
        href = link.attrs['href']

        if href.startswith('mailto:') or href.startswith('javascript:') or '>' in href:
            # skip emails and JS links entirely, as well as malformed html that doesn't close the quote
            continue

        # strip the fragment identifier
        href, _fragment = urldefrag(href)

        try:
            url = httpx.URL(href)
            url = base_url.join(httpx.URL(href))
        except httpx.InvalidURL as err:
            log.error(f'{err} when parsing {href!r}')
            continue

        yield url


@retry_on_busy
def get_response_by_id(db: apsw.Connection, *, response_id: int) -> UrlBodyAndEncoding:
    with db:
        row = db.execute('SELECT url, body, encoding FROM response WHERE id = ?', [response_id]).fetchone()
        assert row
        return row


@retry_on_busy
def get_response_url_by_id(db: apsw.Connection, *, response_id: int) -> ResponseUrl:
    with db:
        row = db.execute('SELECT url FROM response WHERE id = ?', [response_id]).fetchone()
        assert row
        return row


def extract_all_links_from_response(
    encoding: str,
    body: bytes,
    base_url: httpx.URL,
) -> Iterator[httpx.URL]:
    match encoding:
        case 'binary' | 'unknown':
            # log.info(f'skipping {response_url} with encoding {response_row.encoding!r}')
            pass

        case encoding:
            # log.info(f'parsing {response_url} with encoding {response_row.encoding!r}')
            yield from parse_body_for_links(body=body, encoding=encoding, base_url=base_url)


def parse_response_for_links(db: apsw.Connection, *, response_id: int) -> Iterator[httpx.URL]:
    # log.debug(f'loading {response_id}')
    record = get_response_by_id(db, response_id=response_id)
    base_url = httpx.URL(record.url)

    links = set(extract_all_links_from_response(encoding=record.encoding, body=record.body, base_url=base_url))

    for url in links:
        if url.scheme not in ('http', 'https'):
            # log.debug(f'skipping {url} as {url.scheme} is not http/s')
            continue

        if url.host != base_url.host:
            # log.debug(f'skipping {url} as {url.host} is outside of {response_url.host}')
            continue

        yield url


@retry_on_busy
def update_sitemap(db: apsw.Connection, *, source: httpx.URL, target: httpx.URL) -> None:
    with db:
        db.execute(
            """
            INSERT INTO sitemap (source, target)
            VALUES (
                (SELECT id FROM link WHERE url = :source_url),
                (SELECT id FROM link WHERE url = :target_url)
            )
            ON CONFLICT DO NOTHING
            """,
            dict(source_url=str(source), target_url=str(target)),
        )


T = TypeVar('T')


def partition(pred: Callable[[T], bool], it: Iterable[T]) -> tuple[list[T], list[T]]:
    # found via https://giannitedesco.github.io/2020/12/14/a-faster-partition-function.html
    ts = []
    fs = []
    for item in it:
        if pred(item):
            ts.append(item)
        else:
            fs.append(item)
    return ts, fs


@app.command()
def show_response(
    response_id: int,
    config_file: Annotated[Path, ReadableFile] = Path('sites.kdl'),
    database_file: Optional[Path] = None,
) -> None:
    config = parse_config(config_file)
    database_file = database_file or config_file.with_suffix('.sqlite3')

    db = connect(database_file)

    with db:
        table = rich.table.Table(title=f'Outbound links from response-id {response_id}')
        table.add_column('FETCH', justify='right', style='cyan')
        table.add_column('URL')

        site_config = config.sites[0]
        unique_links = parse_response_for_links(db, response_id=response_id)
        will_fetch, skip_fetch = partition(lambda link: site_config.match_url(link), unique_links)
        will_fetch = sorted(str(url) for url in will_fetch)
        skip_fetch = sorted(str(url) for url in skip_fetch)

        for link in will_fetch:
            table.add_row('X', link)

        for link in skip_fetch:
            table.add_row('', link)

        console.print(table)


@app.command()
def crawl(
    config_file: Annotated[Path, ReadableFile] = Path('sites.kdl'),
    database_file: Optional[Path] = None,
    check: bool = True,
    once: bool = False,
    batch_size: int = 50,
    fetch_batch_size: int = 50,
    parse_batch_size: int = 500,
):
    config = parse_config(config_file)
    site_config = config.sites[0]
    log.info(f'waiting {site_config.fetch_delay.total_seconds()} seconds between requests')
    database_file = database_file or config_file.with_suffix('.sqlite3')

    db = connect(database_file, check='quick' if check else None)

    with init_client() as client:
        # insert the starting URL
        insert_link(db, site_config.start_url)

        while True:
            fetch_documents(db=db, config=site_config, client=client, batch_size=fetch_batch_size or batch_size)
            extract_links(db=db, config=site_config, batch_size=parse_batch_size or batch_size)

            if once:
                break

            queued = next_in_fetch_queue(db) or next_in_parse_queue(db)
            if not queued:
                break


@app.command()
def crawl_tree(
    config_file: Annotated[Path, ReadableFile] = Path('sites.kdl'),
    database_file: Optional[Path] = None,
    once: bool = False,
):
    config = parse_config(config_file)
    # console.print(config)

    job_progress = rich.progress.Progress(
        '{task.description}',
        rich.progress.SpinnerColumn(),
        rich.progress.BarColumn(),
        rich.progress.TextColumn('[progress.percentage]{task.percentage:>3.0f}%'),
    )

    for i, site in enumerate(config.sites):
        job_progress.add_task(site.name, total=100 * (i + 1))

    progress_table = rich.table.Table.grid()
    progress_table.add_row(
        rich.panel.Panel.fit(job_progress, title='[b]Sites[/b]', border_style='yellow', padding=(1, 3)),
    )

    all_done = False
    with rich.live.Live(progress_table, refresh_per_second=10):
        while not all_done:
            time.sleep(0.1)
            for job in job_progress.tasks:
                if not job.finished:
                    job_progress.advance(job.id)

            all_done = all(j.finished for j in job_progress.tasks)

    # log.info('Inserting the start URL')
    # with connect(database_file) as db:
    #     insert_link(db, site_config.start_url)
    #
    # with init_client() as client:
    #     while True:
    #         fetch_documents(database_file=database_file, config=site_config, client=client)
    #         extract_links(database_file=database_file, config=site_config)
    #
    #         if once:
    #             break
    #
    #         with connect(database_file) as db:
    #             queued = next_in_fetch_queue(db)
    #
    #         if not queued:
    #             break


@app.command()
def fetch(
    config_file: Annotated[Path, ReadableFile] = Path('sites.kdl'),
    database_file: Optional[Path] = None,
    batch_size: int = 500,
):
    config = parse_config(config_file)
    site_config = config.sites[0]
    database_file = database_file or config_file.with_suffix('.sqlite3')
    db = connect(database_file)

    with init_client() as client:
        fetch_documents(db=db, config=site_config, client=client, batch_size=batch_size)


@app.command()
def explore(
    config_file: Annotated[Path, ReadableFile] = Path('sites.kdl'),
    database_file: Optional[Path] = None,
    batch_size: int = 500,
):
    config = parse_config(config_file)
    site_config = config.sites[0]
    database_file = database_file or config_file.with_suffix('.sqlite3')
    db = connect(database_file)

    extract_links(db=db, config=site_config, batch_size=batch_size)


@app.command()
def validate_config(config_file: Path) -> None:
    config = parse_config(config_file)

    colors = ['bright_black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']

    table = rich.table.Table.grid()
    for i, site in enumerate(config.sites):
        border_color = colors[i % len(colors)]
        table.add_row(
            rich.panel.Panel.fit(rich.pretty.Pretty(site), title=f'[b]{site.name}[/b]', border_style=border_color)
        )

    console.print(table)


@app.command()
def validate_database(
    config_file: Annotated[Path, ReadableFile] = Path('sites.kdl'),
    database_file: Optional[Path] = None,
):
    database_file = database_file or config_file.with_suffix('.sqlite3')
    connect(database_file, check='full')


@app.command()
def queue_url(
    url: str,
    config_file: Annotated[Path, ReadableFile] = Path('sites.kdl'),
    database_file: Optional[Path] = None,
    check: bool = True,
):
    database_file = database_file or config_file.with_suffix('.sqlite3')
    db = connect(database_file, check='quick' if check else None)

    with db:
        parsed_url = httpx.URL(url)
        log.info(f'Inserting {parsed_url!r} into {database_file!r}')
        insert_link(db, parsed_url)


@app.command()
def graph():
    pass


if __name__ == '__main__':
    try:
        app()
    except KeyboardInterrupt:
        pass
