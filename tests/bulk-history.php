<?php
declare(strict_types=1);
// Disposable sqlite test of the bulk state machine. Never touches a real site.
define('YOURLS_DB_PREFIX', 'yourls_');
define('YOURLS_DB_TABLE_URL', 'yourls_url');
define('YOURLS_DB_TABLE_OPTIONS', 'yourls_options');
define('YOURLS_COOKIEKEY', 'test-local-secret-only');
define('YOURLS_USER', 'fixture-admin');
require dirname(__DIR__) . '/src/Policy.php';
require dirname(__DIR__) . '/src/HttpProbe.php';
require dirname(__DIR__) . '/src/Guard.php';
require dirname(__DIR__) . '/src/Reputation.php';
require dirname(__DIR__) . '/src/HistoricalReview.php';
require dirname(__DIR__) . '/src/BulkHistory.php';
use ACh\Yourls\UrlGuard\BulkHistory;
use ACh\Yourls\UrlGuard\HistoricalReview;

final class BulkSqlite
{
    private PDO $pdo;
    public function __construct()
    {
        $this->pdo = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $this->pdo->exec('CREATE TABLE yourls_options (option_id INTEGER PRIMARY KEY AUTOINCREMENT, option_name TEXT UNIQUE, option_value TEXT NOT NULL)');
        $this->pdo->exec('CREATE TABLE yourls_url (keyword TEXT PRIMARY KEY, url TEXT, title TEXT, timestamp TEXT, clicks INTEGER)');
        $this->pdo->exec('CREATE TABLE yourls_ach_guard_candidates (job_id TEXT NOT NULL, keyword TEXT NOT NULL, row_proof TEXT, reason TEXT, result TEXT DEFAULT \'pending\', PRIMARY KEY(job_id, keyword))');
    }
    private function prep(string $sql, array $binds): PDOStatement
    {
        $sql = preg_replace('/ FOR UPDATE$/D', '', $sql);
        if ($sql === 'SELECT NOW() AS started') $sql = "SELECT '2026-11-18 23:59:59' AS started";
        $st = $this->pdo->prepare($sql);
        $st->execute($binds);
        return $st;
    }
    public function exec(string $sql): int|false
    {
        // Table already provisioned in this isolated test; real MySQL CI exercises the DDL.
        if (str_starts_with($sql, 'CREATE TABLE IF NOT EXISTS')) return 0;
        return $this->pdo->exec($sql);
    }
    public function fetchAll(string $sql, array $binds = []): array
    {
        return $this->prep($sql, $binds)->fetchAll(PDO::FETCH_ASSOC);
    }
    public function fetchOne(string $sql, array $binds = []): array|false
    {
        return $this->prep($sql, $binds)->fetch(PDO::FETCH_ASSOC);
    }
    public function fetchObject(string $sql, array $binds = []): object|false
    {
        return $this->prep($sql, $binds)->fetch(PDO::FETCH_OBJ);
    }
    public function fetchAffected(string $sql, array $binds = []): int
    {
        return $this->prep($sql, $binds)->rowCount();
    }
    public function beginTransaction(): bool { return $this->pdo->beginTransaction(); }
    public function inTransaction(): bool { return $this->pdo->inTransaction(); }
    public function commit(): bool { return $this->pdo->commit(); }
    public function rollBack(): bool { return $this->pdo->rollBack(); }
}
function yourls_maybe_unserialize($raw) {return @unserialize((string)$raw, ['allowed_classes' => false]);}
function yourls_sanitize_keyword($key): string {return strtolower((string)$key);}
$db = new BulkSqlite();
function yourls_delete_link_by_keyword($key): int
{
    global $db;
    return $db->fetchAffected('DELETE FROM yourls_url WHERE keyword = :key', ['key' => $key]);
}
$checks=0;
function assertBulk(bool $cond, string $what): void
{
    global $checks;
    $checks++;
    if (!$cond) throw new RuntimeException('FAIL ' . $what);
}
$settings=['mode'=>'enforce'];
$db->fetchAffected('INSERT INTO yourls_options (option_name,option_value) VALUES (:key,:value)',
    ['key'=>'ach_url_guard_settings','value'=>serialize($settings)]);
for($i=0;$i<151;$i++){
    $flagged=($i%3===0);
    $db->fetchAffected('INSERT INTO yourls_url(keyword,url,title,timestamp,clicks) VALUES (:key,:url,:title,:time,:clicks)',[
        'key'=>sprintf('l%04d',$i),
        'url'=>$flagged ? 'https://bit.ly/child?token=NEVER_EXPOSE_'.$i : 'https://example.com/safe/'.$i,
        'title'=>'row-'.$i,
        'time'=>'2026-11-12 10:00:00',
        'clicks'=>$i%2,
    ]);
}
$filters=BulkHistory::filter(['reason'=>'blocked_domain','clicks'=>'zero']);
assertBulk($filters['clicks']==='zero', 'clicks filter normalized');
$invalid=false;
try{BulkHistory::filter(['reason'=>'oops']);}catch(InvalidArgumentException $e){$invalid=true;}
assertBulk($invalid,'unknown reason rejected');
$job=BulkHistory::create($db,'fixture-admin','all',$filters,[]);
$id=$job['id'];
assertBulk(strlen($id)===24 && $job['phase']==='scan','all-matching job created');
assertBulk(BulkHistory::load($db,$id,'someone-else')===null,'job owner separation');
$ownerJobs=BulkHistory::recentJobs($db,'fixture-admin');
assertBulk(count($ownerJobs)===1 && $ownerJobs[0]['id']===$id,'owner can recover jobs');
assertBulk(BulkHistory::recentJobs($db,'someone-else')===[],'other user cannot enumerate jobs');
$passes=0;
while($job['phase']==='scan'){
    $job=BulkHistory::scanStep($db,$id,'fixture-admin');
    $passes++;
    if($passes>20)throw new RuntimeException('Scan never finished');
}
assertBulk($passes>=3 && $job['scanned']===151,'keyset scans all pages');
assertBulk($job['matched']===26,'all matching blocked domain with zero clicks selected');
$cands=$db->fetchAll('SELECT keyword,row_proof,reason FROM yourls_ach_guard_candidates WHERE job_id=:id',['id'=>$id]);
assertBulk(count($cands)===26,'materialized exact candidate set');
assertBulk(!str_contains(serialize($cands),'NEVER_EXPOSE'),'candidate table contains no secret URL query');
$first=$cands[0]['keyword'];
$db->fetchAffected('UPDATE yourls_url SET url=:url WHERE keyword=:keyword',
    ['url'=>'https://example.com/safe/new','keyword'=>$first]);
$db->fetchAffected('INSERT INTO yourls_url(keyword,url,title,timestamp,clicks) VALUES (:key,:url,:title,:time,0)',[
    'key'=>'l0000-new','url'=>'https://bit.ly/new','title'=>'late','time'=>'2026-11-13 11:00:00']);
$invalid=false;
try{BulkHistory::startDeletion($db,$id,'fixture-admin','DELETE 26',false);}
catch(InvalidArgumentException $e){$invalid=true;}
assertBulk($invalid,'confirmation required');
$invalid=false;
try{BulkHistory::startDeletion($db,$id,'fixture-admin','DELETE 25',true);}
catch(InvalidArgumentException $e){$invalid=true;}
assertBulk($invalid,'exact count acknowledgment required');
$job=BulkHistory::startDeletion($db,$id,'fixture-admin','DELETE 26',true);
assertBulk($job['phase']==='delete','confirmed job starts deletion');
$job=BulkHistory::deleteStep($db,$id,'fixture-admin');
assertBulk($job['processed']>0 && $job['phase']==='delete','first chunk persists progress');
assertBulk(BulkHistory::load($db,$id,'fixture-admin')['processed']===$job['processed'],'progress survives new request');
$passes=0;
while($job['phase']==='delete'){
    $job=BulkHistory::deleteStep($db,$id,'fixture-admin');
    if(++$passes>20)throw new RuntimeException('Deletion never finished');
}
assertBulk($job['phase']==='done' && $job['deleted']===25 && $job['skipped']===1,
    'frozen 26 candidate set, changed row skipped; only original 25 deleted');
assertBulk(count($db->fetchAll('SELECT keyword FROM yourls_url WHERE keyword=:key',['key'=>'l0000-new']))===1,
    'new matching link after dry-run never deleted');
assertBulk(count($db->fetchAll('SELECT keyword FROM yourls_url WHERE keyword=:key',['key'=>$first]))===1,
    'stale edited URL never deleted');
assertBulk(BulkHistory::deleteStep($db,$id,'fixture-admin')['deleted']===25,'repeated step inert');
$remaining=$db->fetchOne('SELECT COUNT(*) AS c FROM yourls_url');
assertBulk((int)$remaining['c']===127,'healthy rows preserved including new link');
BulkHistory::clear($db,$id,'fixture-admin');
assertBulk(BulkHistory::load($db,$id,'fixture-admin')===null,'completed report cleared only');
assertBulk((int)$db->fetchOne('SELECT COUNT(*) AS c FROM yourls_url')['c']===127,'clearing report never deletes short URLs');

// Current-page selection, explicit cancel.
$job=BulkHistory::create($db,'fixture-admin','page',BulkHistory::filter(['reason'=>'any']),
    ['l0003','l0004','l0006']);
$job=BulkHistory::scanStep($db,$job['id'],'fixture-admin');
assertBulk($job['phase']==='ready' && $job['matched']===1,'selected page contains only still-existing flagged rows');
$job=BulkHistory::cancel($db,$job['id'],'fixture-admin');
assertBulk($job['phase']==='cancelled','cancel does not delete');
BulkHistory::clear($db,$job['id'],'fixture-admin');

// Policy-change abort before execution.
$job=BulkHistory::create($db,'fixture-admin','page',BulkHistory::filter(['reason'=>'any']),['l0003']);
$job=BulkHistory::scanStep($db,$job['id'],'fixture-admin');
$db->fetchAffected('UPDATE yourls_options SET option_value=:val WHERE option_name=:name',
    ['val'=>serialize(['mode'=>'enforce','blocked_domains'=>[]]),'name'=>'ach_url_guard_settings']);
$job=BulkHistory::startDeletion($db,$job['id'],'fixture-admin','DELETE 1',true);
assertBulk($job['phase']==='paused','policy change prevents any delete');
assertBulk(count($db->fetchAll('SELECT keyword FROM yourls_url WHERE keyword=:key',['key'=>'l0003']))===1,
    'policy change preserves link');
BulkHistory::clear($db,$job['id'],'fixture-admin');
$db->fetchAffected('UPDATE yourls_options SET option_value=:val WHERE option_name=:name',
    ['val'=>serialize($settings),'name'=>'ach_url_guard_settings']);

// 404 scan mode is one URL per request, rechecks exact candidate before deletion.
$probe=static function(string $url,array $settings): array{
    if(str_contains($url,'/missing')) return ['status'=>'deny','reason'=>'http_not_found'];
    if(str_contains($url,'/timeout')) return ['status'=>'unknown','reason'=>'http_inconclusive'];
    return ['status'=>'allow','reason'=>'checks_passed'];
};
$db->fetchAffected('INSERT INTO yourls_url(keyword,url,title,timestamp,clicks) VALUES (:key,:url,:title,:time,0)',[
    'key'=>'net404','url'=>'https://example.com/missing','title'=>'missing','time'=>'2026-11-12 10:00:00']);
$db->fetchAffected('INSERT INTO yourls_url(keyword,url,title,timestamp,clicks) VALUES (:key,:url,:title,:time,0)',[
    'key'=>'nettimeout','url'=>'https://example.com/timeout','title'=>'timeout','time'=>'2026-11-12 10:00:00']);
$job=BulkHistory::create($db,'fixture-admin','page',BulkHistory::filter(['reason'=>'http_not_found']),
    ['net404','nettimeout']);
$passes=0;
while($job['phase']==='scan'){
    $job=BulkHistory::scanStep($db,$job['id'],'fixture-admin',$probe);
    if(++$passes>10)throw new RuntimeException('Network fixture scan stalled');
}
assertBulk($job['matched']===1 && $passes>=2,'network scan selects only definite 404, one probe per step');
$job=BulkHistory::startDeletion($db,$job['id'],'fixture-admin','DELETE 1',true);
$job=BulkHistory::deleteStep($db,$job['id'],'fixture-admin',$probe);
assertBulk($job['phase']==='done' && $job['deleted']===1,'network-backed bulk delete requires re-probe');
assertBulk(count($db->fetchAll('SELECT keyword FROM yourls_url WHERE keyword=:key',['key'=>'nettimeout']))===1,
    'uncertain timeout never mass-deleted');
BulkHistory::clear($db,$job['id'],'fixture-admin');
echo 'PASS '.$checks.' bulk selection/filter/snapshot/chunk/cancel/network-state assertions in disposable SQLite'.PHP_EOL;
