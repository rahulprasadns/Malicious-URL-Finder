// Run with: node --test tests/test_form.js (no npm dependencies).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

test('AJAX errors replace loading text using text, not HTML', () => {
    const html = fs.readFileSync(path.join(__dirname, '../templates/index.html'), 'utf8');
    const script = html.match(/<script>\s*([\s\S]*?)<\/script>/)[1];
    let failure;
    let displayed;
    let emptyCalls = 0;
    const output = {
        empty() { emptyCalls++; displayed = null; return this; },
        append(value) { displayed = value; return this; },
    };
    function $(selector) {
        if (selector === '#text1') return { val: () => 'https://example.com' };
        if (selector === '.show-data') return output;
        if (selector === '<h2>') return { text: value => ({ textContent: value }) };
        throw new Error('Unexpected selector: ' + selector);
    }
    $.ajax = () => ({ done() { return this; }, fail(callback) { failure = callback; } });
    const context = { $, document: { addEventListener() {} }, console };
    vm.createContext(context);
    vm.runInContext(script, context);
    context.myFunction();
    assert.equal(displayed, '<h2>Loading ...</h2>');
    failure({ responseJSON: { error: '<script>not executable</script>' } });
    assert.equal(displayed.textContent, '<script>not executable</script>');
    assert.equal(emptyCalls, 2);
    failure({});
    assert.equal(displayed.textContent, 'Unable to classify this URL. Please try again.');
});
