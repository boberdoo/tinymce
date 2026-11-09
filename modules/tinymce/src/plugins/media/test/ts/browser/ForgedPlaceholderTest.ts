import { describe, it } from '@ephox/bedrock-client';
import { TinyAssertions, TinyHooks } from '@ephox/wrap-mcagar';
import { assert } from 'chai';

import Editor from 'tinymce/core/api/Editor';
import Plugin from 'tinymce/plugins/media/Plugin';

declare const escape: any;

describe('browser.tinymce.plugins.media.ForgedPlaceholderTest', () => {
  const hook = TinyHooks.bddSetupLight<Editor>({
    plugins: 'media',
    toolbar: false,
    media_live_embeds: false,
    base_url: '/project/tinymce/js/tinymce'
  }, [ Plugin ]);

  const placeholder = (object: string, attrs: string) => `<p><img src="x.png" data-mce-object="${object}" ${attrs}></p>`;

  const getContentFor = (editor: Editor, html: string) => {
    editor.setContent(html);
    return editor.getContent();
  };

  it('CVE-2026-47761: should not create elements other than media elements', () => {
    const editor = hook.editor();
    const content = getContentFor(editor, placeholder('script', 'data-mce-p-src="https://evil.example/a.js"'));
    assert.notInclude(content, 'script');
    assert.notInclude(content, 'evil.example');
  });

  it('CVE-2026-47761: should not create elements from a non-lowercase or unknown name', () => {
    const editor = hook.editor();
    assert.notInclude(getContentFor(editor, placeholder('SCRIPT', 'data-mce-p-src="https://evil.example/a.js"')), 'evil.example');
    assert.notInclude(getContentFor(editor, placeholder('img', 'data-mce-p-onerror="alert(1)" data-mce-p-src="x"')), 'onerror');
    assert.notInclude(getContentFor(editor, placeholder('svg', 'data-mce-p-onload="alert(1)"')), 'onload');
  });

  it('CVE-2026-47761: should remove event handlers from placeholder attributes', () => {
    const editor = hook.editor();
    editor.setContent(placeholder('iframe', 'data-mce-p-src="https://safe.example/" data-mce-p-onload="alert(1)"'));
    TinyAssertions.assertContent(editor, '<p><iframe src="https://safe.example/"></iframe></p>');
  });

  it('CVE-2026-47761: should remove script urls from placeholder attributes', () => {
    const editor = hook.editor();
    assert.notInclude(getContentFor(editor, placeholder('iframe', 'data-mce-p-src="javascript:alert(1)"')), 'javascript:');
    assert.notInclude(getContentFor(editor, placeholder('embed', 'data-mce-p-src="javascript:alert(1)"')), 'javascript:');
    assert.notInclude(getContentFor(editor, placeholder('object', 'data-mce-p-data="javascript:alert(1)"')), 'javascript:');
    assert.notInclude(getContentFor(editor, placeholder('iframe', 'data-mce-p-src="data:text/html,<script>alert(1)</script>"')), 'data:text/html');
  });

  it('CVE-2026-47761: should not let a placeholder attribute restore an internal attribute', () => {
    const editor = hook.editor();
    const content = getContentFor(editor, placeholder('iframe', 'data-mce-p-src="https://safe.example/" data-mce-p-data-mce-src="https://evil.example/"'));
    assert.notInclude(content, 'evil.example');
  });

  it('CVE-2026-47761: should sanitize forged preview wrappers', () => {
    const editor = hook.editor();
    const content = getContentFor(editor, '<p><span class="mce-preview-object" data-mce-object="iframe" data-mce-p-src="javascript:alert(1)" data-mce-p-onload="alert(1)"><iframe src="https://safe.example/"></iframe></span></p>');
    assert.notInclude(content, 'javascript:');
    assert.notInclude(content, 'onload');
  });

  it('CVE-2026-47761: should sanitize the inner html of a placeholder', () => {
    const editor = hook.editor();
    const content = getContentFor(editor, placeholder('video', `data-mce-html="${escape('<img src="x" onerror="alert(1)">')}"`));
    assert.notInclude(content, 'onerror');
  });

  it('CVE-2026-47761: should apply sandbox_iframes to forged placeholders', () => {
    const editor = hook.editor();
    editor.options.set('sandbox_iframes', true);
    const content = getContentFor(editor, placeholder('iframe', 'data-mce-p-src="https://safe.example/"'));
    editor.options.unset('sandbox_iframes');
    assert.include(content, 'sandbox=""');
  });

  it('CVE-2026-47761: should apply convert_unsafe_embeds to forged placeholders', () => {
    const editor = hook.editor();
    editor.options.set('convert_unsafe_embeds', true);
    const content = getContentFor(editor, placeholder('embed', 'data-mce-p-src="https://safe.example/a.swf"'));
    editor.options.unset('convert_unsafe_embeds');
    assert.notInclude(content, '<embed');
  });

  it('should keep round tripping real media elements', () => {
    const editor = hook.editor();
    const iframe = '<p><iframe style="float: left;" title="t" src="https://example.com/" width="200" height="100" allowfullscreen="allowfullscreen"></iframe></p>';
    editor.setContent(iframe);
    TinyAssertions.assertContent(editor, iframe);

    const video = '<p><video controls="controls" width="300" height="150"><source src="a.mp4" type="video/mp4"></video></p>';
    editor.setContent(video);
    TinyAssertions.assertContent(editor, video);

    const audio = '<p><audio src="a.mp3" controls="controls"></audio></p>';
    editor.setContent(audio);
    TinyAssertions.assertContent(editor, audio);
  });

  it('should keep round tripping a copied placeholder', () => {
    const editor = hook.editor();
    editor.setContent(placeholder('video', `width="300" height="150" data-mce-p-controls="controls" data-mce-html="${escape('<source src="a.mp4" type="video/mp4">')}"`));
    TinyAssertions.assertContent(editor, '<p><video controls="controls" width="300" height="150"><source src="a.mp4" type="video/mp4"></video></p>');
  });
});
