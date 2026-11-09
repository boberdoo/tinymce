import { Optional } from '@ephox/katamari';

import Editor from 'tinymce/core/api/Editor';
import AstNode from 'tinymce/core/api/html/Node';
import HtmlSerializer from 'tinymce/core/api/html/Serializer';

import * as Options from '../api/Options';
import { Parser } from './Parser';

const parseAndSanitize = (editor: Editor, context: string, html: string): AstNode => {
  const getEditorOption = editor.options.get;
  const sanitize = getEditorOption('xss_sanitization');
  const validate = Options.shouldFilterHtml(editor);
  return Parser(editor.schema, { sanitize, validate }).parse(html, { context });
};

// Placeholder attributes can come from the content, so embeds restored from them need the same
// validation that the editor parser applies to a real embed element
const sanitizeEmbed = (editor: Editor, embed: AstNode): Optional<AstNode> => {
  const getEditorOption = editor.options.get;
  const fragment = Parser(editor.schema, {
    allow_html_data_urls: getEditorOption('allow_html_data_urls'),
    allow_script_urls: getEditorOption('allow_script_urls'),
    allow_svg_data_urls: getEditorOption('allow_svg_data_urls'),
    convert_unsafe_embeds: getEditorOption('convert_unsafe_embeds'),
    sandbox_iframes: getEditorOption('sandbox_iframes'),
    sanitize: getEditorOption('xss_sanitization'),
    validate: true
  }).parse(HtmlSerializer({}, editor.schema).serialize(embed));
  return Optional.from(fragment.firstChild);
};

export {
  parseAndSanitize,
  sanitizeEmbed
};
