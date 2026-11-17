/*
 * Deterministic real-browser focus regression for Issue #10, PR #11.
 * Provide page (isolated Playwright Chromium) and fixtureHtml generated from
 * php -d log_errors=0 tests/bulk-progress-fixture.php.
 * No npm dependency, Production credentials or external HTTP traffic needed.
 */
export default async function runBulkFocusReview(page, fixtureHtml) {
if (typeof page === 'undefined' || typeof fixtureHtml !== 'string') {
    throw new Error('A Playwright page and actual PHP-generated fixtureHtml are required');
}
var requests = [];
var nextRequest = null;
await page.route('https://guard-bulk.test/**', async function (route) {
    var url = route.request().url();
    requests.push(url);
    if (url.includes('/admin/admin-ajax.php?')) {
        if (!nextRequest) throw new Error('Unexpected AJAX request');
        nextRequest(route);
        nextRequest = null;
        return;
    }
    if (url === 'https://guard-bulk.test/fixture') {
        await route.fulfill({status:200, contentType:'text/html; charset=utf-8', body:fixtureHtml});
        return;
    }
    throw new Error('Unexpected fixture URL: ' + url);
});
var cases = [
    ['scan','ready','Ready — preview complete',
        '<form><label>Type DELETE 2217<input name="bulk_confirm_text"/></label>'
        + '<button type="button">Start confirmed background deletion</button></form>'],
    ['scan','error','Worker error — manual retry required',
        '<button type="button">Retry background processing</button>'],
    ['delete','done','Completed','<p>Done</p>'],
    ['delete','paused','Stopped — policy changed','<p>New dry-run needed</p>'],
];
for (var item of cases) {
    var from = item[0], to = item[1], heading = item[2], controls = item[3];
    var receive;
    var requestPromise = new Promise(function (resolve) { receive = resolve; });
    nextRequest = receive;
    await page.goto('https://guard-bulk.test/fixture', {waitUntil:'domcontentloaded'});
    await page.locator('#ach-bulk-live h3').evaluate(function (el, source) {
        el.textContent = source === 'scan' ? 'Scanning — read-only preview' : 'Deleting — confirmed';
    }, from);
    await page.locator('#focus-action').focus();
    var focused = await page.evaluate(function () { return document.activeElement.id; });
    if (focused !== 'focus-action') throw new Error('Fixture focus not established');
    var pendingRoute = await requestPromise;
    await pendingRoute.fulfill({
        status:200, contentType:'application/json',
        body:JSON.stringify({
            ok:true, phase:to, updated:'2026-11-17T12:00:00Z',
            stale:false, scanned:21100, matched:2217,
            processed:0, deleted:0, skipped:0,
            html:'<section><h3>' + heading + '</h3>' + controls + '</section>'
        })
    });
    await page.waitForFunction(function () {
        var pending = document.getElementById('ach-bulk-pending');
        return pending && !pending.hidden && pending.querySelector('section');
    }, null, {timeout:2000});
    var terminal = await page.locator('#ach-bulk-pending').innerText();
    var live = await page.locator('#ach-bulk-poll-message').innerText();
    var retained = await page.evaluate(function () { return document.activeElement.id; });
    if (retained !== 'focus-action' || !terminal.includes(heading) || !live.includes(to)) {
        throw new Error('Transition invisible or focus lost: ' + from + ' -> ' + to);
    }
    if (to === 'ready') {
        await page.locator('#ach-bulk-pending input[name=bulk_confirm_text]').fill('DELETE 2217');
        await page.waitForFunction(function () {
            return document.getElementById('ach-bulk-live').hidden;
        }, null, {timeout:2000});
        var typed = await page.locator('#ach-bulk-pending input[name=bulk_confirm_text]').inputValue();
        var active = await page.evaluate(function () { return document.activeElement.getAttribute('name'); });
        if (typed !== 'DELETE 2217' || active !== 'bulk_confirm_text') {
            throw new Error('Ready form lost focus or entered value');
        }
    }
    console.log('PASS focus-preserving ' + from + ' -> ' + to + ' without full-page reload');
}
// Expired authentication must not look like a transient connectivity error.
var receiveAuth;
var authRequest = new Promise(function (resolve) { receiveAuth = resolve; });
nextRequest = receiveAuth;
await page.goto('https://guard-bulk.test/fixture', {waitUntil:'domcontentloaded'});
var routeAuth = await authRequest;
await routeAuth.fulfill({status:403, contentType:'application/json', body:'{"ok":false}'});
await page.waitForFunction(function () {
    return document.getElementById('ach-bulk-poll-message').textContent.includes('Login expired');
}, null, {timeout:2000});
if (requests.filter(function (url) { return url.includes('/admin/admin-ajax.php?'); }).length !== 5) {
    throw new Error('Unexpected number of status polls or page reloads');
}
console.log('PASS expired-auth instruction and no hidden/repeated destructive requests');
}
