/*
 * Deterministic Chromium regression for REQUIRED-01 in Issue #6.
 * Run with an isolated Playwright browser runner using its page variable.
 * Supply fixtureHtml from: php -d log_errors=0 tests/history-layout-fixture.php
 * Execute this JavaScript with those two variables in the same scope.
 * No npm dependency, Production session, or live customer data is needed.
 */
if (typeof page === 'undefined' || typeof fixtureHtml !== 'string') {
    throw new Error('An isolated Playwright page and synthetic fixtureHtml are required');
}
var unexpectedRequests = [];
page.on('request', function (req) {
    if (!req.url().startsWith('https://guard-layout.test/')) unexpectedRequests.push(req.url());
});
await page.route('https://guard-layout.test/**', async function (route) {
    await route.fulfill({status: 200, contentType: 'text/html; charset=utf-8', body: fixtureHtml});
});
await page.goto('https://guard-layout.test/fixture', {waitUntil: 'domcontentloaded'});
await page.evaluate(async function () { await document.fonts.ready; });
var widths = [1100, 780, 430, 360, 340, 320, 300, 280, 240];
for (var width of widths) {
    await page.setViewportSize({width: width, height: 720});
    await page.waitForTimeout(40);
    var states = await page.evaluate(function () {
        return Array.from(document.querySelectorAll('[data-case]')).map(function (container) {
            var code = container.querySelector('.ach-history-one-line');
            var original = code.querySelector('.ach-history-original');
            var compact = code.querySelector('.ach-history-compact');
            var marker = compact.querySelector('.ach-history-marker');
            var prefix = compact.querySelector('.ach-history-prefix');
            var suffix = compact.querySelector('.ach-history-suffix');
            var b = code.getBoundingClientRect();
            var o = original.getBoundingClientRect();
            var m = marker && marker.getBoundingClientRect();
            var p = prefix && prefix.getBoundingClientRect();
            var s = suffix && suffix.getBoundingClientRect();
            var abbreviated = code.classList.contains('ach-history-abbreviated');
            var button = container.querySelector('button.ach-history-copy');
            return {
                name: container.getAttribute('data-case'),
                shouldAbbreviate: o.width > b.width + 1,
                abbreviated: abbreviated,
                markerVisible: !!m && m.left >= b.left - 1 && m.right <= b.right + 1,
                prefixVisible: !!p && p.width > 1,
                suffixVisible: !!s && s.left >= b.left - 1 && s.right <= b.right + 1,
                preservedSuffix: !!suffix && original.textContent.endsWith(suffix.textContent),
                preservedPrefix: !!prefix && original.textContent.startsWith(prefix.textContent),
                markerAccessible: !!marker && marker.textContent.includes('middle omitted'),
                singleLine: getComputedStyle(code).whiteSpace === 'nowrap',
                visibleCopy: !button || button.getBoundingClientRect().right <= innerWidth + 1,
                correctA11y: original.getAttribute('aria-hidden') === (abbreviated ? 'true' : 'false')
                    && compact.getAttribute('aria-hidden') === (abbreviated ? 'false' : 'true')
            };
        });
    });
    for (var state of states) {
        var okay = state.shouldAbbreviate === state.abbreviated
            && (!state.abbreviated || (state.markerVisible && state.prefixVisible
                && state.suffixVisible && state.preservedPrefix && state.preservedSuffix
                && state.markerAccessible))
            && state.singleLine && state.visibleCopy && state.correctA11y;
        if (!okay) {
            throw new Error('responsive ' + width + 'px ' + state.name + ': ' + JSON.stringify(state));
        }
    }
    console.log('PASS responsive ' + width + 'px (' + states.length + ' cases)');
}
await page.setViewportSize({width: 430, height: 720});
await page.waitForTimeout(40);
await page.evaluate(function () {
    window.__copied = [];
    Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {
        writeText: async function (text) { window.__copied.push({mode: 'modern', text: text}); }
    }});
});
var markupButton = page.locator('[data-case="markup"] button.ach-history-copy');
await markupButton.focus();
await page.keyboard.press('Enter');
await page.waitForFunction(function () { return window.__copied.length === 1; }, null, {timeout: 2000});
var modern = await page.evaluate(function () {
    var button = document.querySelector('[data-case="markup"] button.ach-history-copy');
    return {
        actual: window.__copied[0].text,
        expected: button.getAttribute('data-copy-url'),
        status: document.getElementById('ach-history-copy-status').textContent,
        markupExecuted: !!window.__xss
    };
});
if (modern.actual !== modern.expected || !modern.status.includes('copied') || modern.markupExecuted) {
    throw new Error('modern exact Copy, feedback or inert markup failed');
}
await page.evaluate(function () {
    window.__copied = [];
    Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {
        writeText: async function () { throw new Error('denied'); }
    }});
    document.execCommand = function (operation) {
        window.__copied.push({mode: 'legacy', text: document.activeElement.value});
        return operation === 'copy';
    };
});
var unicodeButton = page.locator('[data-case="unicode"] button.ach-history-copy');
await unicodeButton.focus();
await page.keyboard.press('Enter');
await page.waitForFunction(function () { return window.__copied.length === 1; }, null, {timeout: 2000});
var fallback = await page.evaluate(function () {
    var button = document.querySelector('[data-case="unicode"] button.ach-history-copy');
    return {
        actual: window.__copied[0].text,
        expected: button.getAttribute('data-copy-url'),
        method: window.__copied[0].mode,
        focusRestored: document.activeElement === button
    };
});
if (fallback.actual !== fallback.expected || fallback.method !== 'legacy' || !fallback.focusRestored) {
    throw new Error('legacy Copy exact-value or focus restoration failed');
}
await page.setViewportSize({width: 1100, height: 720});
await page.waitForTimeout(40);
var expanded = await page.locator('[data-case="medium"] code.ach-history-one-line')
    .evaluate(function (el) { return !el.classList.contains('ach-history-abbreviated'); });
if (!expanded) throw new Error('Full label did not return after expanding viewport');
// User font scaling can overflow the same layout width; observing the
// original-value span must update abbreviation without a window resize.
var mediumCode = page.locator('[data-case="medium"] code.ach-history-one-line');
await mediumCode.evaluate(function (el) { el.style.fontSize = '36px'; });
await page.waitForTimeout(60);
if (!(await mediumCode.evaluate(function (el) {
    return el.classList.contains('ach-history-abbreviated');
}))) throw new Error('Large font did not trigger width-aware abbreviation');
await mediumCode.evaluate(function (el) { el.style.fontSize = ''; });
await page.waitForTimeout(60);
if (await mediumCode.evaluate(function (el) {
    return el.classList.contains('ach-history-abbreviated');
})) throw new Error('Original-size font did not restore the full label');

if (unexpectedRequests.length) throw new Error('Unexpected external request count: ' + unexpectedRequests.length);
console.log('PASS exact Copy, keyboard, fallback, URL escaping, resize and font-scale reversibility, no external requests');
