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

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import cast

# Type names only. Parsing goes through defusedxml.sax with DTDs and entities forbidden.
from xml.sax import SAXParseException  # nosec B406
from xml.sax.handler import ContentHandler  # nosec B406
from xml.sax.xmlreader import AttributesImpl, Locator  # nosec B406

import defusedxml.sax
import yaml
from defusedxml import DefusedXmlException

from kasauti.shape.base import MAX_DEPTH, ParseError, RawStatement, check_depth
from kasauti.shape.tokens import quote_if_needed, unquote

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


RECORD = "@"
"""First word of a record: a list item's scalar fields as one statement (``Records``)."""


def parse_json_yaml(
    text: str, *, item_names: tuple[str, ...] = ("name", "Name")
) -> Iterator[RawStatement]:
    """``item_names``: keys whose value names a list item."""
    walker = _Walker(item_names, None)
    yield from walker.document(_compose(text))


def parse_records(text: str, names: Mapping[str, str]) -> tuple[list[RawStatement], frozenset[str]]:
    """The statements of a document read as records (``Records``), and its top-level keys.

    Each list item's scalar fields, and those of the objects inside it (as ``outer.inner``),
    become one statement, ``@`` and each key and value in key order, under the item's header;
    its lists follow beneath it. ``names``: list key -> the field that names its items
    (``SecurityGroups`` -> ``GroupId``); other items are numbered from 0. A key given twice in
    one object is refused: which of the two a reader keeps differs from reader to reader."""
    walker = _Walker((), names)
    statements = list(walker.document(_compose(text)))
    return statements, frozenset(walker.top_keys)


_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
"""libyaml's parser where PyYAML was built with it: the pure-Python scanner spends about 5 s
on a mebibyte of small JSON values (M2.31 hostile files). Only its events are used."""


def _compose(text: str) -> yaml.Node | None:
    try:
        return _nodes(yaml.parse(text, Loader=_LOADER))
    except yaml.MarkedYAMLError as err:
        line = err.problem_mark.line + 1 if err.problem_mark else None
        raise ParseError(f"invalid JSON/YAML: {err.problem}", line) from err
    except yaml.YAMLError as err:
        raise ParseError(f"invalid JSON/YAML: {err}") from err


def _nodes(events: Iterable[yaml.Event]) -> yaml.Node | None:
    """The document's node tree, built from the parser's events with a stack of its own.

    PyYAML's composer and libyaml's recurse once per nesting level: a few hundred ``[`` raise
    RecursionError in the first, and the second, compiled, has no recursion limit at all. The
    parsers themselves are iterative, so nesting is bounded here, as it arrives. Aliases are
    refused as they arrive (a small document with nested aliases expands exponentially), and
    tags are never resolved: nothing is constructed, every scalar stays text."""
    tree = _Tree()
    for event in events:
        tree.take(event)
    return tree.root


class _Tree:
    def __init__(self) -> None:
        self.root: yaml.Node | None = None
        self.stack: list[tuple[yaml.CollectionNode, list[yaml.Node]]] = []
        """Open collections, each with the key waiting for its value (mappings only)."""
        self.documents = 0

    def take(self, event: yaml.Event) -> None:
        line = event.start_mark.line + 1 if event.start_mark else None
        if isinstance(event, yaml.AliasEvent):
            raise ParseError("YAML aliases are not accepted", line)
        if isinstance(event, yaml.DocumentStartEvent):
            self.documents += 1
            if self.documents > 1:
                raise ParseError("a JSON/YAML configuration must be one document", line)
        elif isinstance(event, yaml.CollectionEndEvent):
            node, _ = self.stack.pop()
            node.end_mark = event.end_mark
        elif isinstance(event, yaml.ScalarEvent):
            self.add(yaml.ScalarNode(_TEXT, event.value, *_marks(event)))
        elif isinstance(event, yaml.SequenceStartEvent | yaml.MappingStartEvent):
            if len(self.stack) >= MAX_DEPTH:
                raise ParseError(f"blocks nested more than {MAX_DEPTH} levels deep", line)
            kind = (
                yaml.SequenceNode
                if isinstance(event, yaml.SequenceStartEvent)
                else yaml.MappingNode
            )
            node = kind(_TEXT, [], *_marks(event))
            self.add(node)
            self.stack.append((node, []))

    def add(self, node: yaml.Node) -> None:
        if not self.stack:
            self.root = node
            return
        parent, pending = self.stack[-1]
        if isinstance(parent, yaml.SequenceNode):
            parent.value.append(node)
        elif pending:
            parent.value.append((pending.pop(), node))
        else:
            pending.append(node)


def _marks(event: yaml.Event) -> tuple[yaml.Mark | None, yaml.Mark | None]:
    """An event's start and end. libyaml's marks are its own class, with the same ``line``
    and ``column`` the walker reads."""
    return cast("yaml.Mark | None", event.start_mark), cast("yaml.Mark | None", event.end_mark)


_TEXT = "tag:yaml.org,2002:str"
"""Every node's tag: the walker reads text, and no tag is ever resolved to a type."""


class _Walker:
    def __init__(self, item_names: tuple[str, ...], records: Mapping[str, str] | None) -> None:
        self.seen: set[int] = set()
        self.item_names = item_names
        self.records = records
        self.top_keys: list[str] = []

    def document(self, root: yaml.Node | None) -> Iterator[RawStatement]:
        if root is None:
            return
        if isinstance(root, yaml.MappingNode):
            yield from self.mapping(root, ())
        elif isinstance(root, yaml.SequenceNode):
            yield from self.sequence("item", root, ())
        else:
            raise ParseError("a JSON/YAML configuration must be an object or a list", 1)

    def _visit(self, node: yaml.Node) -> None:
        if id(node) in self.seen:
            raise ParseError("YAML aliases are not accepted", node.start_mark.line + 1)
        self.seen.add(id(node))
        if len(self.seen) > MAX_NODES:
            raise ParseError(f"more than {MAX_NODES} JSON/YAML nodes")

    def _keys(self, node: yaml.MappingNode) -> Iterator[tuple[str, yaml.ScalarNode, yaml.Node]]:
        """Each key of ``node`` with its value; in records, a key given twice is refused."""
        given: set[str] = set()
        for key_node, value in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                raise ParseError("only scalar keys are supported", key_node.start_mark.line + 1)
            self._visit(key_node)
            key = str(key_node.value)
            if self.records is not None and key in given:
                raise ParseError(f"the key {key!r} is given twice", key_node.start_mark.line + 1)
            given.add(key)
            yield key, key_node, value

    def mapping(self, node: yaml.MappingNode, path: tuple[str, ...]) -> Iterator[RawStatement]:
        self._visit(node)
        for raw_key, key_node, value in self._keys(node):
            if not path:
                self.top_keys.append(raw_key)
            key = quote_if_needed(raw_key)
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
        if self.records is None:
            names = self.item_names
        else:
            field = self.records.get(unquote(key))
            names = (field,) if field else ()
        for index, item in enumerate(node.value):
            line = item.start_mark.line + 1
            if isinstance(item, yaml.ScalarNode):
                self._visit(item)
                yield RawStatement(path, f"{key} {_scalar(item)}", line, _end(item))
                continue
            header = f"{key} {_item_name(item, index, names)}"
            check_depth(len(path) + 1, line)
            yield RawStatement(path, header, line, line)
            if isinstance(item, yaml.MappingNode) and self.records is not None:
                yield from self.record(item, (*path, header))
            elif isinstance(item, yaml.MappingNode):
                yield from self.mapping(item, (*path, header))
            else:
                yield from self.sequence(key, item, (*path, header))

    def record(self, node: yaml.MappingNode, path: tuple[str, ...]) -> Iterator[RawStatement]:
        fields: list[tuple[str, yaml.ScalarNode]] = []
        lists: list[tuple[str, yaml.Node]] = []
        self._fold(node, "", fields, lists, depth=len(path), taken=set())
        if fields:
            start = min(v.start_mark.line + 1 for _, v in fields)
            end = max(_end(v) for _, v in fields)
            ordered = sorted(fields, key=lambda f: f[0])
            words = " ".join(f"{quote_if_needed(k)} {_scalar(v)}" for k, v in ordered)
            yield RawStatement(path, f"{RECORD} {words}", start, max(start, end))
        for key, value in lists:
            check_depth(len(path) + 1, value.start_mark.line + 1)
            yield from self.sequence(quote_if_needed(key), value, path)

    def _fold(
        self,
        node: yaml.MappingNode,
        prefix: str,
        fields: list[tuple[str, yaml.ScalarNode]],
        lists: list[tuple[str, yaml.Node]],
        *,
        depth: int,
        taken: set[str],
    ) -> None:
        self._visit(node)
        for raw_key, key_node, value in self._keys(node):
            key = f"{prefix}{raw_key}"
            if key in taken:
                # {"A.B": 1, "A": {"B": 2}} folds to the same field twice.
                raise ParseError(f"the key {key!r} is given twice", key_node.start_mark.line + 1)
            taken.add(key)
            if isinstance(value, yaml.ScalarNode):
                self._visit(value)
                fields.append((key, value))
            elif isinstance(value, yaml.MappingNode):
                check_depth(depth + key.count(".") + 2, key_node.start_mark.line + 1)
                self._fold(value, f"{key}.", fields, lists, depth=depth, taken=taken)
            else:
                lists.append((key, value))


def _scalar(node: yaml.ScalarNode) -> str:
    return quote_if_needed(str(node.value))


def _end(node: yaml.Node) -> int:
    # end_mark points just past the value; a value ending a line reports the same line.
    end = node.end_mark
    return end.line + 1 if end.column > 0 or end.line == node.start_mark.line else end.line


def _item_name(item: yaml.Node, index: int, names: tuple[str, ...]) -> str:
    if isinstance(item, yaml.MappingNode):
        found = {
            str(k.value): v
            for k, v in item.value
            if isinstance(k, yaml.ScalarNode) and isinstance(v, yaml.ScalarNode)
        }
        for name in names:
            if name in found:
                return quote_if_needed(str(found[name].value))
    return str(index)
