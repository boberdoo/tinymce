import { context, describe, it } from '@ephox/bedrock-client';
import { Arr } from '@ephox/katamari';
import { assert } from 'chai';

import DomParser from 'tinymce/core/api/html/DomParser';
import Schema from 'tinymce/core/api/html/Schema';
import HtmlSerializer from 'tinymce/core/api/html/Serializer';

describe('browser.tinymce.core.html.SanitizationSvgScopeTest', () => {
  const svgSchemaSettings = { extended_valid_elements: 'svg[*]' };

  const parseWithSchema = (schema: Schema, sanitize: boolean, html: string) => {
    const parser = DomParser({ sanitize, validate: true, forced_root_block: false }, schema);
    return HtmlSerializer({}, schema).serialize(parser.parse(html));
  };

  Arr.each([ { sanitize: true, label: 'default' }, { sanitize: false, label: 'default' }, { sanitize: true, label: 'svg' }, { sanitize: false, label: 'svg' }], ({ sanitize, label }) => {
    context(`sanitize: ${sanitize}, schema: ${label}`, () => {
      const schema = Schema(label === 'svg' ? svgSchemaSettings : {});
      const parse = (sanitize: boolean, html: string) => parseWithSchema(schema, sanitize, html);

      const assertTrailingImgFiltered = (svgHtml: string) => {
        const output = parse(sanitize, `${svgHtml}<img src="x.png" onerror="alert(1)">`);
        assert.notInclude(output, 'onerror');
        assert.include(output, '<img src="x.png">');
      };

      it('CVE-2026-47760: should filter html elements following a nested svg', () =>
        assertTrailingImgFiltered('<svg><svg></svg></svg>'));

      it('CVE-2026-47760: should filter html elements following deeply nested svgs', () =>
        assertTrailingImgFiltered('<svg><svg><svg><svg></svg></svg></svg></svg>'));

      it('CVE-2026-47760: should filter html elements following sibling svgs', () =>
        assertTrailingImgFiltered('<svg></svg><svg></svg>'));

      it('CVE-2026-47760: should filter html elements following sibling svgs inside a nested svg', () =>
        assertTrailingImgFiltered('<svg><svg></svg><svg></svg></svg>'));

      it('CVE-2026-47760: should filter html elements nested inside a parent following a nested svg', () => {
        const output = parse(sanitize, '<div><svg><svg></svg></svg></div><div><a href="javascript:alert(1)" onclick="alert(1)">x</a></div>');
        assert.notInclude(output, 'onclick');
        assert.notInclude(output, 'javascript:');
      });

      it('CVE-2026-47760: should remove elements not in the schema following a nested svg', () => {
        const output = parse(sanitize, '<svg><svg></svg></svg><script>alert(1)</script><p>text</p>');
        assert.notInclude(output, 'alert(1)');
        assert.include(output, '<p>text</p>');
      });
    });
  });

  it('CVE-2026-47760: should keep the svg markup itself and still sanitize inside it', () => {
    const output = parseWithSchema(Schema(svgSchemaSettings), true, '<svg><svg><circle r="1" onclick="alert(1)"></circle></svg></svg><p>text</p>');
    assert.include(output, '<circle r="1">');
    assert.notInclude(output, 'onclick');
    assert.include(output, '<p>text</p>');
  });
});
