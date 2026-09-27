"""Structured shape families (PLAN §6.1): XML, and JSON/YAML (TODO M2.14, M2.15).

Both render a document into the same statements the text families produce, so one mapping
language serves every family:

* a leaf becomes ``"<key> <value>"`` under the path of its ancestors;
* an element or list item identified by a ``name`` renders as ``"<element> <name>"``
  (``entry localhost.localdomain``); an unnamed list item as ``"<key> <index>"``;
* a value containing spaces is quoted, so a ``<STR>`` slot captures it whole.

Security: XML is parsed with defusedxml (no DTDs, entities or external references: no XXE,
no billion laughs). YAML/JSON is *composed* with PyYAML's SafeLoader, never constructed, and
aliases are refused, because a small document with nested aliases can expand exponentially.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

# Type names only. Parsing goes through defusedxml.sax with DTDs and entities forbidden.
from xml.sax import SAXParseException  # nosec B406
from xml.sax.handler import ContentHandler  # nosec B406
from xml.sax.xmlreader import AttributesImpl, Locator  # nosec B406

import defusedxml.sax
import yaml
from defusedxml import DefusedXmlException

from kasauti.shape.base import MAX_DEPTH, ParseError, RawStatement, check_depth
from kasauti.shape.tokens import quote_if_needed

MAX_NODES = 2_000_000
"""Upper bound on rendered nodes, a second line of defence after the file-size limit."""

# --- XML ----------------------------------------------------------------------------------------


@dataclass
class _Frame:
    rendered: str
    line: int
    order: int
    text: list[str] = field(default_factory=list)
    has_children: bool = False


class _XmlHandler(ContentHandler):
    def __init__(self) -> None:
        super().__init__()
        self.locator: Locator | None = None
        self.stack: list[_Frame] = []
        self.out: list[tuple[int, RawStatement]] = []
        self.count = 0

    def setDocumentLocator(self, locator: Locator) -> None:  # noqa: N802 - SAX API
        self.locator = locator

    def _line(self) -> int:
        line = self.locator.getLineNumber() if self.locator else None
        return line or 1

    def startElement(self, name: str, attrs: AttributesImpl) -> None:  # noqa: N802
        self.count += 1
        if self.count > MAX_NODES:
            raise ParseError(f"more than {MAX_NODES} XML elements")
        check_depth(len(self.stack) + 1, self._line())
        if self.stack:
            self.stack[-1].has_children = True
        label = attrs.get("name")
        rendered = name if label is None else f"{name} {quote_if_needed(label)}"
        self.stack.append(_Frame(rendered, self._line(), self.count))

    def characters(self, content: str) -> None:
        if self.stack:
            self.stack[-1].text.append(content)

    def endElement(self, name: str) -> None:  # noqa: N802
        frame = self.stack.pop()
        path = tuple(f.rendered for f in self.stack)
        value = "".join(frame.text).strip()
        text = frame.rendered
        if not frame.has_children and value:
            text = f"{frame.rendered} {quote_if_needed(value)}"
        self.out.append((frame.order, RawStatement(path, text, frame.line, self._line())))


def parse_xml(text: str) -> Iterator[RawStatement]:
    handler = _XmlHandler()
    try:
        defusedxml.sax.parseString(text.encode("utf-8"), handler, forbid_dtd=True)
    except SAXParseException as err:
        raise ParseError(f"invalid XML: {err.getMessage()}", err.getLineNumber()) from err
    except DefusedXmlException as err:
        raise ParseError(f"refused unsafe XML ({type(err).__name__})") from err
    for _, statement in sorted(handler.out, key=lambda item: item[0]):
        yield statement


# --- JSON / YAML --------------------------------------------------------------------------------


def parse_json_yaml(text: str) -> Iterator[RawStatement]:
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except RecursionError:
        # PyYAML's composer recurses once per nesting level (a few hundred JSON "[" are
        # enough); refused like any nesting past MAX_DEPTH (M2.07 review).
        raise ParseError(f"blocks nested more than {MAX_DEPTH} levels deep") from None
    except yaml.MarkedYAMLError as err:
        line = err.problem_mark.line + 1 if err.problem_mark else None
        raise ParseError(f"invalid JSON/YAML: {err.problem}", line) from err
    except yaml.YAMLError as err:
        raise ParseError(f"invalid JSON/YAML: {err}") from err
    if root is None:
        return
    walker = _Walker()
    if isinstance(root, yaml.MappingNode):
        yield from walker.mapping(root, ())
    elif isinstance(root, yaml.SequenceNode):
        yield from walker.sequence("item", root, ())
    else:
        raise ParseError("a JSON/YAML configuration must be an object or a list", 1)


class _Walker:
    def __init__(self) -> None:
        self.seen: set[int] = set()

    def _visit(self, node: yaml.Node) -> None:
        if id(node) in self.seen:
            raise ParseError("YAML aliases are not accepted", node.start_mark.line + 1)
        self.seen.add(id(node))
        if len(self.seen) > MAX_NODES:
            raise ParseError(f"more than {MAX_NODES} JSON/YAML nodes")

    def mapping(self, node: yaml.MappingNode, path: tuple[str, ...]) -> Iterator[RawStatement]:
        self._visit(node)
        for key_node, value in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                raise ParseError("only scalar keys are supported", key_node.start_mark.line + 1)
            self._visit(key_node)
            key = quote_if_needed(str(key_node.value))
            line = key_node.start_mark.line + 1
            if isinstance(value, yaml.ScalarNode):
                self._visit(value)
                yield RawStatement(path, f"{key} {_scalar(value)}", line, _end(value))
            elif isinstance(value, yaml.MappingNode):
                check_depth(len(path) + 1, line)
                yield RawStatement(path, key, line, line)
                yield from self.mapping(value, (*path, key))
            else:
                check_depth(len(path) + 1, line)
                yield from self.sequence(key, value, path)

    def sequence(self, key: str, node: yaml.Node, path: tuple[str, ...]) -> Iterator[RawStatement]:
        self._visit(node)
        for index, item in enumerate(node.value):
            line = item.start_mark.line + 1
            if isinstance(item, yaml.ScalarNode):
                self._visit(item)
                yield RawStatement(path, f"{key} {_scalar(item)}", line, _end(item))
                continue
            header = f"{key} {_item_name(item, index)}"
            check_depth(len(path) + 1, line)
            yield RawStatement(path, header, line, line)
            if isinstance(item, yaml.MappingNode):
                yield from self.mapping(item, (*path, header))
            else:
                yield from self.sequence(key, item, (*path, header))


def _scalar(node: yaml.ScalarNode) -> str:
    return quote_if_needed(str(node.value))


def _end(node: yaml.Node) -> int:
    # end_mark points just past the value; a value ending a line reports the same line.
    end = node.end_mark
    return end.line + 1 if end.column > 0 or end.line == node.start_mark.line else end.line


def _item_name(item: yaml.Node, index: int) -> str:
    if isinstance(item, yaml.MappingNode):
        for key_node, value in item.value:
            if (
                isinstance(key_node, yaml.ScalarNode)
                and key_node.value in ("name", "Name")
                and isinstance(value, yaml.ScalarNode)
            ):
                return quote_if_needed(str(value.value))
    return str(index)
