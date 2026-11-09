import { context, describe, it } from '@ephox/bedrock-client';
import { TinyAssertions, TinyHooks } from '@ephox/wrap-mcagar';
import { assert } from 'chai';

import Editor from 'tinymce/core/api/Editor';

declare const escape: any;

describe('browser.tinymce.core.content.ForgedInternalContentTest', () => {
  const hook = TinyHooks.bddSetupLight<Editor>({
    base_url: '/project/tinymce/js/tinymce',
    protect: [ /<\?php.*?\?>/g ]
  }, []);

  const protectedComment = (html: string) => `<!--mce:protected ${escape(html)}-->`;

  context('CVE-2026-47759: forged data-mce-* attributes', () => {
    it('should not let data-mce-href override href', () => {
      const editor = hook.editor();
      editor.setContent('<p><a href="https://safe.example/" data-mce-href="https://evil.example/">link</a></p>');
      TinyAssertions.assertContent(editor, '<p><a href="https://safe.example/">link</a></p>');
      assert.equal(editor.dom.select('a')[0].getAttribute('data-mce-href'), 'https://safe.example/');
    });

    it('should not let data-mce-src override src', () => {
      const editor = hook.editor();
      editor.setContent('<p><img src="https://safe.example/a.png" data-mce-src="https://evil.example/a.png"></p>');
      TinyAssertions.assertContent(editor, '<p><img src="https://safe.example/a.png"></p>');
    });

    it('should not let data-mce-style override style', () => {
      const editor = hook.editor();
      editor.setContent('<p style="color: red;" data-mce-style="position: fixed; top: 0;">text</p>');
      TinyAssertions.assertContent(editor, '<p style="color: red;">text</p>');
      assert.equal(editor.dom.select('p')[0].getAttribute('data-mce-style'), 'color: red;');
    });

    it('should strip internal attributes without a matching attribute', () => {
      const editor = hook.editor();
      editor.setContent('<p data-mce-style="position: fixed;"><a data-mce-href="https://evil.example/" id="a">a</a><img alt="b" data-mce-src="https://evil.example/a.png"></p>');
      const paragraph = editor.dom.select('p')[0];
      assert.isFalse(paragraph.hasAttribute('data-mce-style'));
      assert.isFalse(editor.dom.select('a')[0].hasAttribute('data-mce-href'));
      assert.isFalse(editor.dom.select('img')[0].hasAttribute('data-mce-src'));
    });

    it('should strip internal attributes when the matching attribute is empty', () => {
      const editor = hook.editor();
      editor.setContent('<p><a id="a" href="" data-mce-href="https://evil.example/">a</a></p>');
      assert.isFalse(editor.dom.select('a')[0].hasAttribute('data-mce-href'));
      assert.notInclude(editor.getContent(), 'evil.example');
    });

    it('should strip a forged internal attribute when the url is a data or blob uri', () => {
      const editor = hook.editor();
      editor.setContent('<p><a href="data:text/plain,a" data-mce-href="https://evil.example/">a</a></p>', { format: 'html' });
      const link = editor.dom.select('a')[0];
      assert.notEqual(link.getAttribute('data-mce-href'), 'https://evil.example/');
      assert.notInclude(editor.getContent(), 'evil.example');
    });

    it('should strip forged internal attributes when inserting content', () => {
      const editor = hook.editor();
      editor.setContent('<p>a</p>');
      editor.insertContent('<a href="https://safe.example/" data-mce-href="https://evil.example/">b</a>');
      assert.notInclude(editor.getContent(), 'evil.example');
      assert.include(editor.getContent(), 'href="https://safe.example/"');
    });

    it('should strip forged internal attributes when inserted content is invalid in its context', () => {
      const editor = hook.editor();
      editor.setContent('<h1>a</h1>');
      editor.insertContent('<div><a href="https://safe.example/" data-mce-href="https://evil.example/">b</a></div>');
      assert.notInclude(editor.getContent(), 'evil.example');
      assert.include(editor.getContent(), 'href="https://safe.example/"');
    });

    it('should keep generating internal attributes for normal content', () => {
      const editor = hook.editor();
      editor.setContent('<p><a href="https://safe.example/">link</a></p>');
      assert.equal(editor.dom.select('a')[0].getAttribute('data-mce-href'), 'https://safe.example/');
      TinyAssertions.assertContent(editor, '<p><a href="https://safe.example/">link</a></p>');
    });
  });

  context('CVE-2026-47762: forged mce:protected comments', () => {
    it('should remove a forged comment that does not match a protect pattern', () => {
      const editor = hook.editor();
      editor.setContent(`<p>a</p>${protectedComment('<img src="x" onerror="alert(1)">')}`);
      TinyAssertions.assertContent(editor, '<p>a</p>');
    });

    it('should remove a forged comment that only partially matches a protect pattern', () => {
      const editor = hook.editor();
      editor.setContent(`<p>a</p>${protectedComment('<?php a ?><img src="x" onerror="alert(1)">')}`);
      assert.notInclude(editor.getContent(), 'onerror');
    });

    it('should remove a forged comment with the payload ahead of a matching section', () => {
      const editor = hook.editor();
      editor.setContent(`<p>a</p>${protectedComment('<img src="x" onerror="alert(1)"><?php a ?>')}`);
      assert.notInclude(editor.getContent(), 'onerror');
    });

    it('should keep restoring content captured by a protect pattern, including on repeat serialization', () => {
      const editor = hook.editor();
      editor.setContent('<p>a</p><?php echo 1; ?><p>b</p><?php echo 2; ?>');
      const expected = '<p>a</p>\n<?php echo 1; ?>\n<p>b</p>\n<?php echo 2; ?>';
      assert.equal(editor.getContent(), expected);
      assert.equal(editor.getContent(), expected);
    });
  });
});
